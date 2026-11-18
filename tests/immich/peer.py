"""Bind a returned opaque snapshot to the exact source receipt and same hosted Core run."""
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import stat
import subprocess


class PeerError(ValueError):
    pass


def require(value, code):
    if not value:
        raise PeerError(code)


def git_revision(root, expected, paths):
    require(re.fullmatch(r"[0-9a-f]{40}", expected), "invalid_source_revision")
    commit = subprocess.check_output(["git", "-C", str(root), "rev-parse", "HEAD"],
                                     stderr=subprocess.DEVNULL, timeout=10).decode().strip()
    require(commit == expected, "source_revision_mismatch")
    clean = subprocess.run(["git", "-C", str(root), "diff", "--quiet", "HEAD", "--", *paths], timeout=10)
    require(clean.returncode == 0, "modified_trial_source")


def unique_pairs(pairs):
    value = dict(pairs)
    require(len(value) == len(pairs), "duplicate_receipt_key")
    return value


def exact_transport(receipt, bindings):
    expected = dict(version=1, kind="image-immich-peer-transport", **bindings,
                    source_ciphertext_removed=True, withdrawn_provider_unavailable=True,
                    peer_restores=2, all_eight_copies_deleted=True, providers_final_usage_zero=True,
                    kvm_joined=True, guest_private_state_removed=True)
    require(type(receipt) is dict and set(receipt) == set(expected), "transport_fields")
    require(all(type(receipt[k]) is type(v) and receipt[k] == v for k, v in expected.items()),
            "transport_binding")


def source_cipher_removed(folder):
    require({p.name for p in folder.iterdir()} == {"receipt.json"}, "source_cipher_still_present")
    info = (folder / "receipt.json").lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == os.getuid()
            and stat.S_IMODE(info.st_mode) == 0o600, "source_receipt_file")


def returned_cipher(folder, count, sha):
    require([p.name for p in folder.iterdir()] == ["snapshot.pgp"], "unexpected_received_files")
    path = folder / "snapshot.pgp"
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), "rb") as stream:
        st = os.fstat(stream.fileno())
        require(stat.S_ISREG(st.st_mode) and st.st_uid == os.getuid() and st.st_nlink == 1
                and not (st.st_mode & 0o077) and st.st_size == count, "received_cipher_file")
        require(hashlib.file_digest(stream, "sha256").hexdigest() == sha, "received_cipher_digest")


class PeerTransport:
    def __init__(self, core, core_revision, image, image_revision, runner):
        self.core = Path(core)
        self.image_revision = image_revision
        self.core_revision = core_revision
        require(self.core.is_absolute() and self.core.resolve(strict=True) == self.core, "core_checkout")
        git_revision(self.core, core_revision, ["tests/integration/image-topology-host.sh"])
        git_revision(image, image_revision, ["tests/immich", "scripts/immich_snapshot.py", "upstream.lock.json"])
        require(os.environ["GITHUB_SHA"] == core_revision, "workflow_revision")
        self.run = {k: os.environ[v] for k, v in
                    (("run_id", "GITHUB_RUN_ID"), ("run_attempt", "GITHUB_RUN_ATTEMPT"))}
        require(all(re.fullmatch("[1-9][0-9]*", v) for v in self.run.values()), "run_identity")
        self.adapter = self.core / "tests/integration/image-topology-host.sh"
        require(self.adapter.resolve(strict=True) == self.adapter and self.adapter.is_file()
                and self.adapter.stat().st_uid == os.getuid(), "core_adapter")
        self.runner = runner
        self.evidence = runner / "image-topology-receipt.json"
        require(not os.path.lexists(self.evidence), "existing_transport_receipt")

    def transfer(self, bundle, delivery, created):
        bindings = dict(core_revision=self.core_revision, image_revision=self.image_revision,
                        **self.run, cipher_bytes=created["cipher_bytes"], cipher_sha256=created["cipher_sha256"])
        require(type(bindings["cipher_bytes"]) is int and 4 <= bindings["cipher_bytes"] <= 1024**2
                and re.fullmatch("[0-9a-f]{64}", bindings["cipher_sha256"]), "bounded_ciphertext")
        require(bundle.parent == delivery.parent and bundle.parent.parent == self.runner
                and {p.name for p in bundle.iterdir()} == {"snapshot.pgp", "receipt.json"}
                and not list(delivery.iterdir()), "handoff_directories")
        # Stream only the adapter's closed public diagnostics. No SQL, key, PNG or bearer token as input.
        process = subprocess.Popen([self.adapter, "transport", bundle, delivery], start_new_session=True)
        try:
            require(process.wait(timeout=10800) == 0, "core_transport_failed")
        finally:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGTERM)
                try:
                    process.wait(timeout=90)
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait(timeout=10)
        with os.fdopen(os.open(self.evidence, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), "rb") as stream:
            info = os.fstat(stream.fileno())
            require(stat.S_ISREG(info.st_mode) and 0 < info.st_size <= 4096, "transport_receipt_size")
            receipt = json.loads(stream.read(4097), object_pairs_hook=unique_pairs)
        exact_transport(receipt, bindings)
        source_cipher_removed(bundle)
        return bindings
