#!/usr/bin/env python3
"""Restore a real private Immich installation from a local or Core peer-recovered ciphertext."""
import argparse
import base64
import gzip
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import signal
import struct
import subprocess
import sys
import tempfile
import time
import zlib

from peer import PeerError, PeerTransport, returned_cipher

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
FOLDERS = {"upload", "library", "profile", "thumbs", "encoded-video", "backups"}
LIMIT = 64 * 1024 * 1024
UPSTREAM = "db355f79d910bbfc6378117ed10868493c97b922"


class Failure(Exception):
    pass


def check(condition, code):
    if not condition:
        raise Failure(code)


def command(args, *, stdin=None, env=None, timeout=120):
    result = subprocess.run(args, input=stdin, capture_output=True, timeout=timeout, env=env)
    if result.returncode:
        # Only fixture-defined codes can leave the private runner. Never log raw API/SQL output.
        code = re.search(rb"TRIAL_API_[a-z_]+_[0-9]{1,3}", result.stderr)
        if code:
            raise Failure(code.group().decode())
        code = re.search(rb'"error":\s*"([A-Z_]{3,70})"', result.stderr + result.stdout)
        if code:
            raise Failure(code.group(1).decode())
        raise Failure(f"process_exit_{result.returncode}")
    return result.stdout


class Project:
    def __init__(self, prefix, suffix):
        self.name = f"{prefix}-{suffix}"
        check(re.fullmatch(r"imageproof[0-9a-f]{12}-(source|receiver)", self.name), "project_guard")
        self.env = {**os.environ, "IMAGE_TRIAL_DB_PASSWORD": secrets.token_hex(24)}
        self.owned = False

    def compose(self, *args, **kwargs):
        return command(["docker", "compose", "--project-name", self.name, "--file",
                        str(HERE / "compose.yml"), *args], env=self.env, **kwargs)

    def objects(self):
        label = "label=com.docker.compose.project=" + self.name
        return [item for group in (["ps", "-aq"], ["volume", "ls", "-q"], ["network", "ls", "-q"])
                for item in command(["docker", *group, "--filter", label]).splitlines()]

    def claim(self):
        check(not self.objects(), "project_collision")
        self.owned = True

    def clean(self):
        if self.owned:
            self.compose("down", "--volumes", "--remove-orphans", "--timeout", "15")
            check(not self.objects(), "project_cleanup_incomplete")
            self.owned = False

    def container(self, role):
        cid = self.compose("ps", "--all", "--quiet", role).decode().strip()
        check(re.fullmatch(r"[0-9a-f]{12,64}", cid), "container_identity")
        label = command(["docker", "inspect", "-f",
                         '{{index .Config.Labels "com.docker.compose.project"}}', cid])
        check(label.decode().strip() == self.name, "container_owner")
        return cid

    def database(self):
        self.compose("up", "-d", "--pull", "never", "database", "redis")
        internal = command(["docker", "network", "inspect", "-f", "{{.Internal}}", self.name + "_default"])
        check(internal.strip() == b"true", "private_network")
        # The image's first boot also runs a temporary Unix-only initialization server.
        for _ in range(90):
            try:
                answer = self.compose("exec", "-T", "database", "pg_isready", "-h", "127.0.0.1",
                                      "-U", "postgres", "-d", "immich", timeout=5)
                if b"accepting connections" in answer:
                    break
            except Failure:
                pass
            time.sleep(1)
        else:
            raise Failure("database_unavailable")

    def no_public_ports(self):
        for role in ("database", "redis", "server"):
            bindings = command(["docker", "inspect", "-f", "{{json .HostConfig.PortBindings}}",
                                self.container(role)])
            check(not json.loads(bindings), "public_port")

    def client(self, payload):
        output = self.compose("run", "--no-deps", "--rm", "-T", "--pull", "never", "client",
                              "--input-type=module", "-e", (HERE / "client.mjs").read_text(),
                              stdin=json.dumps(payload).encode(), timeout=240)
        return json.loads(output)


def picture():
    def chunk(name, data):
        return struct.pack(">I", len(data)) + name + data + struct.pack(">I", zlib.crc32(name + data))
    width, height = 64, 48
    rows = b"".join(b"\0" + bytes(v for x in range(width) for v in
        ((4*x) % 256, (5*y) % 256, (x*y) % 256)) for y in range(height))
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">2I5B", width, height, 8, 2, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(rows)) + chunk(b"IEND", b""))


def snapshot(operation, *args):
    raw = command([sys.executable, "-B", str(REPO / "scripts/immich_snapshot.py"), operation, *args,
                   "--max-bytes", str(LIMIT), "--timeout-seconds", "90"], timeout=110)
    return json.loads(raw)


def trial(root, source, receiver, report, peer):
    def stage(name):
        report["stage"] = name
        print("Immich restore trial: " + name, flush=True)

    stage("acquire_pinned_release")
    lock = json.loads((REPO / "upstream.lock.json").read_text())
    check((lock["commit"], lock["release"]) == (UPSTREAM, "v3.2.4"), "upstream_lock")
    source.claim()
    receiver.claim()
    config = json.loads(source.compose("config", "--format", "json"))
    images = {config["services"][name]["image"] for name in ("server", "database", "redis")}
    check(len(images) == 3 and all(re.fullmatch(r"[a-z0-9./-]+@sha256:[0-9a-f]{64}", i)
                                  for i in images), "image_digest_required")
    source.compose("pull", "server", "redis", "database", timeout=420)
    server_image = config["services"]["server"]["image"]
    revision = command(["docker", "image", "inspect", "-f",
                        '{{index .Config.Labels "org.opencontainers.image.revision"}}', server_image])
    check(revision.decode().strip() == UPSTREAM, "server_source_revision")
    report.update(immich_revision=UPSTREAM, immich_version="3.2.4", image_digests=sorted(images))

    stage("original_owner_upload_and_read")
    source.database()
    source.compose("up", "-d", "--pull", "never", "server")
    source.no_public_ports()
    png = picture()
    inputs = dict(credentials={"email": "owner@example.test", "password": secrets.token_hex(24)},
                  image=base64.b64encode(png).decode())
    expected = source.client({**inputs, "seed": True})
    check(expected["originalSha256"] == hashlib.sha256(png).hexdigest()
          and expected["bytes"] == len(png), "source_asset")
    report.update(original_authenticated_read=True, original_bytes=len(png))

    stage("quiesce_database_and_media")
    source.compose("stop", "--timeout", "30", "server")
    server = source.container("server")
    check(command(["docker", "inspect", "-f", "{{.State.Running}}", server]).strip() == b"false",
          "application_not_stopped")
    prepared = root / "quiesced"
    prepared.mkdir(mode=0o700)
    # All application writers are stopped. PostgreSQL owns the consistent logical dump.
    dump = source.compose("exec", "-T", "database", "pg_dump", "--clean", "--if-exists",
                          "--username=postgres", "--dbname=immich")
    check(0 < len(dump) <= LIMIT and b"PostgreSQL database dump complete" in dump, "sql_dump")
    command(["docker", "cp", server + ":/data/.", str(prepared)])
    check({p.name for p in prepared.iterdir()} == FOLDERS, "media_inventory")
    (prepared / "database.sql.gz").write_bytes(gzip.compress(dump, mtime=0))
    dump_hash = hashlib.sha256(dump).digest()
    del dump
    report.update(application_quiesced=True, postgres_dump_completed=True)

    stage("encrypt_and_separate_owner_key")
    bundle = root / "owner"
    created = snapshot("create", "--source", prepared, "--output", bundle, "--quiesced-copy")
    check(created["encryption"] == "OpenPGP-AES256" and re.fullmatch(
        r"[0-9a-f]{64}", created["cipher_sha256"]), "encryption")
    report.update(cipher_bytes=created["cipher_bytes"], cipher_sha256=created["cipher_sha256"])
    delivery = root / "received"
    delivery.mkdir(mode=0o700)
    key_dir = root / "owner-key"
    key_dir.mkdir(mode=0o700)
    key = (bundle / "recovery.key").rename(key_dir / "recovery.key")
    # Destroy only this synthetic source project, after the normal authenticated original read.
    source.clean()
    shutil.rmtree(prepared)
    report["source_project_removed"] = True
    stage("private_ciphertext_handoff")
    if peer is None:
        shutil.copyfile(bundle / "snapshot.pgp", delivery / "snapshot.pgp")
        (delivery / "snapshot.pgp").chmod(0o600)
    else:
        bindings = peer.transfer(bundle, delivery, created)
        report.update(**bindings, peer_storage_exercised=True, peer_transport_verified=True)
    returned_cipher(delivery, created["cipher_bytes"], created["cipher_sha256"])
    # After local handoff discard the source archive. Core already removed its source ciphertext.
    shutil.rmtree(bundle)
    report["received_ciphertext_only"] = True

    stage("owner_snapshot_restore")
    recovered = root / "recovered"
    restored = snapshot("restore", "--bundle", delivery, "--recovery-key-file", key,
                        "--expected-sha256", created["cipher_sha256"], "--output", recovered)
    check(restored["openpgp_integrity_verified"] and restored["manifest_verified"], "snapshot_restore")
    check({p.name for p in recovered.iterdir()} == FOLDERS | {"database.sql.gz"}, "restored_inventory")
    report.update(openpgp_integrity_verified=True, decrypted_manifest_verified=True)

    stage("restore_into_empty_postgres")
    receiver.database()
    sql = ["exec", "-T", "database", "psql", "-X", "-A", "-t", "-U", "postgres",
           "-d", "immich", "--set", "ON_ERROR_STOP=on"]
    tables = receiver.compose(*sql, "-c", "SELECT count(*) FROM pg_tables WHERE schemaname='public'")
    check(tables.strip() == b"0", "receiver_database_not_empty")
    with gzip.open(recovered / "database.sql.gz", "rb") as archive:
        dump = archive.read(LIMIT + 1)
    check(len(dump) <= LIMIT and hashlib.sha256(dump).digest() == dump_hash, "restored_dump_changed")
    # Same search_path adjustment as the pinned upstream's Linux restore instructions.
    dump = dump.replace(b"SELECT pg_catalog.set_config('search_path', '', false);",
                        b"SELECT pg_catalog.set_config('search_path', 'public, pg_catalog', true);")
    receiver.compose(*sql, "--single-transaction", stdin=dump, timeout=120)
    report.update(empty_postgres_verified=True, postgres_restore_completed=True)

    stage("install_recovered_media")
    receiver.compose("create", "--pull", "never", "server")
    recovered_server = receiver.container("server")
    for folder in sorted(FOLDERS):
        command(["docker", "cp", str(recovered / folder), recovered_server + ":/data/"])
    stage("start_recovered_server")
    receiver.compose("start", "server")
    receiver.no_public_ports()
    stage("fresh_recovered_owner_read")
    observed = receiver.client({**inputs, "seed": False, "expected": expected})
    check(observed == expected, "recovered_asset")
    report.update(fresh_owner_login=True, owner_identity_preserved=True, album_membership_preserved=True,
                  anonymous_read_denied=True, original_bytes_identical=True, private_network_verified=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--core-checkout", type=Path)
    parser.add_argument("--core-revision")
    parser.add_argument("--image-revision")
    args = parser.parse_args()
    joined = args.core_checkout is not None
    if any(value is not None for value in vars(args).values()) and not all(vars(args).values()):
        parser.error("a joined proof requires the Core checkout and both exact source revisions")
    def interrupt(_number, _frame):
        raise Failure("trial_interrupted")

    signal.signal(signal.SIGTERM, interrupt)
    os.umask(0o077)
    check(os.environ.get("GITHUB_ACTIONS") == "true" and os.environ.get("RUNNER_ENVIRONMENT")
          == "github-hosted" and re.fullmatch(r"[0-9]+", os.environ.get("GITHUB_RUN_ID", "")),
          "hosted_disposable_runner_required")
    runner = Path(os.environ["RUNNER_TEMP"]).resolve(strict=True)
    evidence = runner / "immich-restore-result.json"
    check(not evidence.exists(), "existing_report")
    prefix = "imageproof" + secrets.token_hex(6)
    source, receiver = Project(prefix, "source"), Project(prefix, "receiver")
    report = dict(schema=1, status="failed", stage="prepare",
                  proof_mode="core-peer" if joined else "local-ciphertext",
                  image_revision=args.image_revision if joined else os.environ["GITHUB_SHA"],
                  peer_storage_exercised=False)
    scratch = None
    try:
        peer = PeerTransport(args.core_checkout, args.core_revision, REPO, args.image_revision,
                             runner) if joined else None
        with tempfile.TemporaryDirectory(prefix="img-", dir=runner) as scratch:
            try:
                trial(Path(scratch), source, receiver, report, peer)
            finally:
                for project in (receiver, source):
                    try:
                        project.clean()
                    except (Failure, subprocess.TimeoutExpired):
                        report["cleanup_failed"] = True
        check(not report.get("cleanup_failed"), "docker_cleanup")
        report.update(stage="complete", status="passed")
    except (Failure, OSError, ValueError, KeyError, subprocess.TimeoutExpired) as error:
        report["reason"] = str(error) if isinstance(error, (Failure, PeerError)) else type(error).__name__
    report["private_scratch_removed"] = scratch is None or not Path(scratch).exists()
    report["docker_resources_removed"] = not source.objects() and not receiver.objects()
    if not (report["private_scratch_removed"] and report["docker_resources_removed"]):
        report["status"] = "failed"
    with evidence.open("x") as output:
        json.dump(report, output, sort_keys=True, indent=2)
    print(json.dumps(report, sort_keys=True))
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    sys.exit(main())
