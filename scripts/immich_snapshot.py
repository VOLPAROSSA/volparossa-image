#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Private, streamed snapshots of an explicitly quiesced Immich copy.

No running database, Immich server, peer transfer or automatic dependency installation.
The only encryption format is standard GnuPG OpenPGP, not an application cipher.
"""

import argparse
import base64
from contextlib import contextmanager
import ctypes
import errno
import gzip
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import secrets
import shutil
import signal
import socket
import stat
import subprocess
import sys
import tarfile
import tempfile
import threading

GPG = "/usr/bin/gpg"
AGENT = "/usr/bin/gpg-agent"
GPGCONF = "/usr/bin/gpgconf"
ASSETS = {"upload", "library", "profile", "thumbs", "encoded-video", "backups"}
CHUNK = 65536
MAX_FILES = 100000
MAX_MANIFEST = 32 * 1024 * 1024
# Leave room for archive metadata and OpenPGP overhead below the core's 64 GiB
# ciphertext limit. Explicit larger standalone snapshots still need splitting
# before they can use that separate storage API; never truncate their contents.
DEFAULT_BYTES = 60 * 1024**3
MANIFEST = "manifest.json"


class SnapshotError(Exception):
    """Closed diagnostic, never a private path or subprocess log."""


def require(condition, code="SNAPSHOT_INVALID"):
    if not condition:
        raise SnapshotError(code)


def canonical(value):
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode()


def identity(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_nlink, info.st_size,
            info.st_mtime_ns, info.st_ctime_ns)


def safe_name(name):
    require(isinstance(name, str) and 0 < len(name.encode("utf-8")) <= 240)
    parts = name.split("/")
    require(all(part not in ("", ".", "..") for part in parts)
            and not any(ord(c) < 32 or ord(c) == 127 or c == "\\" for c in name))
    require(name == "database.sql.gz" or parts[0] in ASSETS)
    return parts


def exact_directory(path):
    path = Path(os.path.abspath(path))
    require(path == path.resolve(strict=True) and path.is_dir(), "UNSAFE_DIRECTORY")
    return path


def new_target(path, forbidden):
    path = Path(os.path.abspath(path))
    parent = exact_directory(path.parent)
    parent_info = parent.stat()
    require(parent_info.st_uid == os.getuid() and stat.S_IMODE(parent_info.st_mode) == 0o700,
            "UNSAFE_OUTPUT_PARENT")
    require(not path.exists() and not path.is_symlink(), "OUTPUT_ALREADY_EXISTS")
    require(not path.is_relative_to(forbidden) and not forbidden.is_relative_to(path),
            "OVERLAPPING_INPUT_OUTPUT")
    return path


@contextmanager
def regular(root_fd, name, expected=None):
    parts = safe_name(name)
    directory = os.dup(root_fd)
    opened = None
    try:
        for part in parts[:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
            os.close(directory)
            directory = child
        opened = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
        info = os.fstat(opened)
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1, "UNSAFE_SOURCE_ENTRY")
        require(expected is None or identity(info) == expected, "SOURCE_CHANGED")
        with os.fdopen(opened, "rb") as stream:
            opened = None
            yield stream, identity(info)
            require(identity(os.fstat(stream.fileno())) == identity(info), "SOURCE_CHANGED")
    finally:
        if opened is not None:
            os.close(opened)
        os.close(directory)


def inventory(root_fd, max_bytes):
    entries, total = {}, 0
    for directory, children, files, fd in os.fwalk(".", dir_fd=root_fd, follow_symlinks=False):
        for name in sorted(children + files):
            relative = str(PurePosixPath(directory) / name)
            safe_name(relative)
            info = os.stat(name, dir_fd=fd, follow_symlinks=False)
            is_dir = stat.S_ISDIR(info.st_mode)
            require(is_dir or (stat.S_ISREG(info.st_mode) and info.st_nlink == 1),
                    "UNSAFE_SOURCE_ENTRY")
            require(not (relative == "database.sql.gz" and is_dir), "DATABASE_DUMP_REQUIRED")
            require(not (relative in ASSETS and not is_dir), "UNSAFE_SOURCE_ENTRY")
            entries[relative] = (is_dir, identity(info))
            if not is_dir:
                total += info.st_size
            require(len(entries) <= MAX_FILES and total <= max_bytes, "SOURCE_LIMIT_EXCEEDED")
    require("database.sql.gz" in entries and entries["database.sql.gz"][1][4] > 0,
            "DATABASE_DUMP_REQUIRED")
    require(any(name in entries for name in ("upload", "library")), "ASSETS_REQUIRED")
    return entries


def validate_database(root_fd, expected, max_bytes):
    with regular(root_fd, "database.sql.gz", expected) as (source, _):
        with gzip.GzipFile(fileobj=source) as dump:
            total = 0
            while chunk := dump.read(CHUNK):
                total += len(chunk)
                require(total <= max_bytes, "DATABASE_LIMIT_EXCEEDED")
            require(total > 0, "DATABASE_DUMP_EMPTY")


def stop(process):
    if process.poll() is None:
        os.killpg(process.pid, signal.SIGTERM)
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        os.killpg(process.pid, signal.SIGKILL)
        process.wait(timeout=5)


def agent_child(directory, descriptor):
    # Socket activation keeps the real gpg-agent in the foreground: our child PID
    # is the agent, not a daemonizing launcher. No global agent/socket is touched.
    os.dup2(descriptor, 3, inheritable=True)
    os.set_inheritable(3, True)
    if descriptor != 3:
        os.close(descriptor)
    env = {"LISTEN_PID": str(os.getpid()), "LISTEN_FDS": "1", "LISTEN_FDNAMES": "std"}
    os.execve(AGENT, [AGENT, "--no-options", "--homedir", directory, "--supervised",
                     "--disable-scdaemon", "--no-allow-external-cache", "--batch"], env)


@contextmanager
def private_agent(parent):
    require(all(Path(tool).is_file() for tool in (GPG, AGENT, GPGCONF)), "GNUPG_REQUIRED")
    with tempfile.TemporaryDirectory(prefix="g-", dir=parent) as directory:
        os.chmod(directory, 0o700)
        # gpgconf itself can create the home-specific runtime directory. Predict
        # Debian GnuPG's documented/source-pinned filename first, acquire it only
        # when absent, then require gpgconf's independently computed exact match.
        # This SHA1/z-base32 is solely GnuPG's socket filename, NOT cryptography
        # for snapshot contents, authentication or key derivation.
        runtime_parent = Path(f"/run/user/{os.getuid()}/gnupg")
        own_runtime = runtime_parent.parent.exists()
        runtime = Path(directory)
        if own_runtime:
            require(runtime_parent.is_dir() and runtime_parent.resolve() == runtime_parent,
                    "PRIVATE_GNUPG_RUNTIME_REQUIRED")
            suffix = base64.b32encode(hashlib.sha1(os.fsencode(directory), usedforsecurity=False).digest()[:15])
            suffix = suffix.translate(bytes.maketrans(b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567",
                                                      b"ybndrfg8ejkmcpqxot1uwisza345h769")).decode("ascii")
            runtime = runtime_parent / ("d." + suffix)
            info = runtime_parent.stat()
            require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid()
                    and info.st_mode & 0o077 == 0, "INVALID_AGENT_RUNTIME")
            require(not runtime.exists() and not runtime.is_symlink(), "AGENT_RUNTIME_ALREADY_EXISTS")
            runtime.mkdir(mode=0o700)
        runtime_identity = (runtime.stat().st_dev, runtime.stat().st_ino)
        socket_identity = None
        try:
            result = subprocess.run([GPGCONF, "--homedir", directory, "--list-dirs", "agent-socket"],
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=5, check=True)
            require(len(result.stdout) < 256, "INVALID_AGENT_SOCKET")
            address = runtime / "S.gpg-agent"
            require(result.stdout.decode("utf-8").strip() == str(address), "UNEXPECTED_AGENT_SOCKET")
            require(len(os.fsencode(address)) < 104, "AGENT_PARENT_PATH_TOO_LONG")
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
                listener.bind(str(address))
                socket_identity = (address.stat().st_dev, address.stat().st_ino)
                listener.listen(4)
                process = subprocess.Popen([sys.executable, "-I", str(Path(__file__).resolve()),
                    "_agent", directory, str(listener.fileno())], pass_fds=(listener.fileno(),),
                    stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                    start_new_session=True)
                try:
                    yield directory
                finally:
                    stop(process)
        finally:
            info = runtime.lstat()
            require((info.st_dev, info.st_ino) == runtime_identity and stat.S_ISDIR(info.st_mode)
                    and info.st_uid == os.getuid(), "AGENT_RUNTIME_CHANGED")
            if socket_identity is not None and address.exists():
                info = address.lstat()
                require((info.st_dev, info.st_ino) == socket_identity and stat.S_ISSOCK(info.st_mode),
                        "AGENT_SOCKET_CHANGED")
                address.unlink()
            if own_runtime:
                runtime.rmdir()  # Empty exact owned directory only, never recursive/global cleanup.


@contextmanager
def crypt_process(directory, key, *, encrypt, output, timeout_seconds, input_stream=subprocess.PIPE):
    secret_read, secret_write = os.pipe()
    process = None
    timer = None
    with tempfile.TemporaryFile(dir=directory) as status:
        try:
            os.write(secret_write, key + b"\n")
            os.close(secret_write)
            secret_write = None
            command = [GPG, "--no-options", "--homedir", directory, "--no-autostart",
                "--batch", "--no-tty", "--pinentry-mode", "loopback", "--no-symkey-cache",
                "--no-random-seed-file", "--disable-dirmngr", "--no-auto-key-retrieve",
                "--passphrase-fd", str(secret_read), "--status-fd", str(status.fileno())]
            if encrypt:
                command += ["--cipher-algo", "AES256", "--compress-algo", "none",
                            "--force-mdc", "--set-filename", "", "--symmetric"]
            else:
                command += ["--decrypt"]
            process = subprocess.Popen(command, stdin=input_stream, stdout=output,
                stderr=subprocess.DEVNULL, pass_fds=(secret_read, status.fileno()),
                start_new_session=True, env={"LC_ALL": "C"})
            os.close(secret_read)
            secret_read = None
            def expire():
                try:
                    process.kill()
                except ProcessLookupError:
                    pass
            timer = threading.Timer(timeout_seconds, expire)
            timer.daemon = True
            timer.start()
            yield process
            require(process.wait(timeout=10) == 0, "OPENPGP_FAILED")
            status.seek(0)
            report = status.read(65537)
            require(len(report) <= 65536, "OPENPGP_STATUS_LIMIT")
            if encrypt:
                require(b"[GNUPG:] END_ENCRYPTION" in report, "OPENPGP_INCOMPLETE")
            else:
                require(b"[GNUPG:] DECRYPTION_OKAY" in report and b"[GNUPG:] GOODMDC" in report
                        and b"[GNUPG:] DECRYPTION_INFO 2 9 0" in report,
                        "OPENPGP_INTEGRITY_REQUIRED")
        finally:
            if timer is not None:
                timer.cancel()
                timer.join()
            if process is not None:
                stop(process)
                if process.stdin is not None:
                    try:
                        process.stdin.close()
                    except BrokenPipeError:
                        pass
                if process.stdout is not None:
                    process.stdout.close()
            for descriptor in (secret_read, secret_write):
                if descriptor is not None:
                    os.close(descriptor)


class HashedReader:
    def __init__(self, source):
        self.source, self.hash = source, hashlib.sha256()

    def read(self, size):
        chunk = self.source.read(min(size, CHUNK))
        self.hash.update(chunk)
        return chunk


def write_tar(root_fd, entries, destination):
    records = []
    with tarfile.open(fileobj=destination, mode="w|", format=tarfile.USTAR_FORMAT,
                      encoding="utf-8", errors="strict") as archive:
        for name, (directory, expected) in sorted(entries.items()):
            member = tarfile.TarInfo("data/" + name)
            member.mode = 0o700 if directory else 0o600
            member.type = tarfile.DIRTYPE if directory else tarfile.REGTYPE
            member.size = 0 if directory else expected[4]
            if directory:
                archive.addfile(member)
                records.append(dict(path=name, kind="directory"))
            else:
                with regular(root_fd, name, expected) as (source, _):
                    reader = HashedReader(source)
                    archive.addfile(member, reader)
                    require(source.read(1) == b"", "SOURCE_CHANGED")
                records.append(dict(path=name, kind="file", bytes=member.size,
                                    sha256=reader.hash.hexdigest()))
        manifest = canonical(dict(version=1, kind="immich-quiesced-snapshot", entries=records))
        require(len(manifest) <= MAX_MANIFEST, "MANIFEST_LIMIT_EXCEEDED")
        member = tarfile.TarInfo(MANIFEST)
        member.mode, member.size = 0o600, len(manifest)
        archive.addfile(member, io.BytesIO(manifest))


def private_write(path, data):
    with open(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600), "wb") as output:
        output.write(data)
        output.flush()
        os.fsync(output.fileno())


def publish(staging, target):
    # Linux renameat2(RENAME_NOREPLACE): never replace even an empty existing directory.
    libc = ctypes.CDLL(None, use_errno=True)
    operation = libc.renameat2
    operation.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
    operation.restype = ctypes.c_int
    result = operation(-100, os.fsencode(staging), -100, os.fsencode(target), 1)
    if result != 0:
        require(ctypes.get_errno() != errno.EEXIST, "OUTPUT_ALREADY_EXISTS")
        raise SnapshotError("SNAPSHOT_PUBLICATION_FAILED")
    fd = os.open(target.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def create(source, output, *, quiesced_copy=False, max_bytes=DEFAULT_BYTES, timeout_seconds=3600):
    require(quiesced_copy is True, "QUIESCED_COPY_ACK_REQUIRED")
    require(type(max_bytes) is int and 0 < max_bytes <= 1024**4, "INVALID_BYTE_LIMIT")
    require(type(timeout_seconds) is int and 1 <= timeout_seconds <= 86400, "INVALID_TIMEOUT")
    source = exact_directory(source)
    target = new_target(output, source)
    root_fd = os.open(source, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    staging = Path(tempfile.mkdtemp(prefix="s-", dir=target.parent))
    try:
        entries = inventory(root_fd, max_bytes)
        validate_database(root_fd, entries["database.sql.gz"][1], max_bytes)
        key = secrets.token_hex(32).encode("ascii")
        private_write(staging / "recovery.key", key + b"\n")
        cipher = staging / "snapshot.pgp"
        with open(os.open(cipher, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb") as encrypted:
            with private_agent(target.parent) as home:
                with crypt_process(home, key, encrypt=True, output=encrypted,
                                   timeout_seconds=timeout_seconds) as process:
                    write_tar(root_fd, entries, process.stdin)
                    process.stdin.close()
            encrypted.flush()
            os.fsync(encrypted.fileno())
        require(inventory(root_fd, max_bytes) == entries, "SOURCE_CHANGED")
        with cipher.open("rb") as stream:
            digest = hashlib.file_digest(stream, "sha256").hexdigest()
        receipt = dict(version=1, kind="volparossa-immich-snapshot", cipher_file="snapshot.pgp",
            cipher_sha256=digest, cipher_bytes=cipher.stat().st_size, encryption="OpenPGP-AES256",
            source_consistency="operator-asserted-quiesced-copy")
        private_write(staging / "receipt.json", canonical(receipt) + b"\n")
        publish(staging, target)
        return receipt
    finally:
        os.close(root_fd)
        if staging.exists():
            shutil.rmtree(staging)


def exact_read(source, size):
    output = bytearray()
    while len(output) < size:
        data = source.read(min(size - len(output), CHUNK))
        require(data, "TRUNCATED_ARCHIVE")
        output.extend(data)
    return bytes(output)


def restore_tar(source, staging, max_bytes):
    records, total, manifest = [], 0, None
    seen = set()
    while True:
        header = exact_read(source, 512)
        if header == bytes(512):
            require(exact_read(source, 512) == bytes(512), "INVALID_TAR_END")
            break
        member = tarfile.TarInfo.frombuf(header, encoding="utf-8", errors="strict")
        require(member.type in (tarfile.REGTYPE, tarfile.DIRTYPE) and not member.linkname
                and member.size >= 0 and manifest is None, "UNSAFE_ARCHIVE_ENTRY")
        if member.name == MANIFEST:
            require(member.isfile() and member.size <= MAX_MANIFEST, "INVALID_MANIFEST")
            manifest = exact_read(source, member.size)
        else:
            require(member.name.startswith("data/"), "UNSAFE_ARCHIVE_ENTRY")
            name = member.name[5:].rstrip("/") if member.isdir() else member.name[5:]
            safe_name(name)
            require(name not in seen and len(seen) < MAX_FILES, "DUPLICATE_ARCHIVE_ENTRY")
            seen.add(name)
            output = staging / name
            require(output.parent.is_dir(), "INVALID_ARCHIVE_ORDER")
            if member.isdir():
                require(member.size == 0, "INVALID_DIRECTORY")
                output.mkdir(mode=0o700)
                records.append(dict(path=name, kind="directory"))
            else:
                total += member.size
                require(total <= max_bytes, "RESTORE_LIMIT_EXCEEDED")
                digest = hashlib.sha256()
                with open(os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600), "wb") as restored:
                    remaining = member.size
                    while remaining:
                        chunk = exact_read(source, min(remaining, CHUNK))
                        remaining -= len(chunk)
                        restored.write(chunk)
                        digest.update(chunk)
                    restored.flush()
                    os.fsync(restored.fileno())
                records.append(dict(path=name, kind="file", bytes=member.size, sha256=digest.hexdigest()))
        padding = (-member.size) % 512
        require(exact_read(source, padding) == bytes(padding), "INVALID_TAR_PADDING")
    trailing = 0
    while chunk := source.read(CHUNK):
        trailing += len(chunk)
        require(trailing <= 10240 and not any(chunk), "UNEXPECTED_TRAILING_DATA")
    require(manifest == canonical(dict(version=1, kind="immich-quiesced-snapshot", entries=records)),
            "MANIFEST_MISMATCH")
    return len(records), total


def restore(bundle, output, *, expected_sha256, max_bytes=DEFAULT_BYTES, timeout_seconds=3600):
    require(re.fullmatch(r"[0-9a-f]{64}", expected_sha256 or ""), "EXPECTED_CIPHER_HASH_REQUIRED")
    require(type(max_bytes) is int and 0 < max_bytes <= 1024**4, "INVALID_BYTE_LIMIT")
    require(type(timeout_seconds) is int and 1 <= timeout_seconds <= 86400, "INVALID_TIMEOUT")
    bundle = exact_directory(bundle)
    require(bundle.stat().st_uid == os.getuid() and bundle.stat().st_mode & 0o077 == 0,
            "PRIVATE_BUNDLE_REQUIRED")
    target = new_target(output, bundle)
    key_path = bundle / "recovery.key"
    key_fd = os.open(key_path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(key_fd, "rb") as secret:
        info = os.fstat(secret.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == os.getuid()
                and info.st_mode & 0o077 == 0 and info.st_size == 65, "PRIVATE_KEY_REQUIRED")
        raw = secret.read(66)
        require(re.fullmatch(rb"[0-9a-f]{64}\n", raw), "INVALID_RECOVERY_KEY")
        key = raw[:-1]
    cipher_fd = os.open(bundle / "snapshot.pgp", os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    staging = Path(tempfile.mkdtemp(prefix="r-", dir=target.parent))
    try:
        with os.fdopen(cipher_fd, "rb") as cipher:
            info = os.fstat(cipher.fileno())
            require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and
                    info.st_size <= max_bytes + MAX_MANIFEST + MAX_FILES * 2048, "INVALID_CIPHER_FILE")
            digest, remaining = hashlib.sha256(), info.st_size
            while remaining:
                chunk = cipher.read(min(remaining, CHUNK))
                require(chunk, "CIPHER_CHANGED")
                remaining -= len(chunk)
                digest.update(chunk)
            require(cipher.read(1) == b"" and identity(os.fstat(cipher.fileno())) == identity(info),
                    "CIPHER_CHANGED")
            require(digest.hexdigest() == expected_sha256, "CIPHER_HASH_MISMATCH")
            cipher.seek(0)
            with private_agent(target.parent) as home:
                # Feed the bounded regular file directly, rather than allocating it or a
                # plaintext archive. Decrypt stdout is parsed incrementally below.
                with crypt_process(home, key, encrypt=False, output=subprocess.PIPE,
                                   timeout_seconds=timeout_seconds, input_stream=cipher) as process:
                    count, total = restore_tar(process.stdout, staging, max_bytes)
            require(identity(os.fstat(cipher.fileno())) == identity(info), "CIPHER_CHANGED")
        root_fd = os.open(staging, os.O_RDONLY | os.O_DIRECTORY)
        try:
            entries = inventory(root_fd, max_bytes)
            validate_database(root_fd, entries["database.sql.gz"][1], max_bytes)
        finally:
            os.close(root_fd)
        publish(staging, target)
        return dict(version=1, kind="volparossa-immich-restore", restored=True,
                    entries=count, bytes=total, cipher_sha256=expected_sha256,
                    openpgp_integrity_verified=True, manifest_verified=True)
    finally:
        if staging.exists():
            shutil.rmtree(staging)


def main():
    if len(sys.argv) == 4 and sys.argv[1] == "_agent":
        agent_child(sys.argv[2], int(sys.argv[3]))
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("create", "restore"):
        command = commands.add_parser(name)
        command.add_argument("--output", type=Path, required=True)
        command.add_argument("--max-bytes", type=int, default=DEFAULT_BYTES)
        command.add_argument("--timeout-seconds", type=int, default=3600)
        if name == "create":
            command.add_argument("--source", type=Path, required=True)
            command.add_argument("--quiesced-copy", action="store_true")
        else:
            command.add_argument("--bundle", type=Path, required=True)
            command.add_argument("--expected-sha256", required=True)
    args = parser.parse_args()
    signal.signal(signal.SIGTERM, lambda *_: (_ for _ in ()).throw(SnapshotError("INTERRUPTED")))
    try:
        require(1 <= args.timeout_seconds <= 86400, "INVALID_TIMEOUT")
        options = dict(max_bytes=args.max_bytes, timeout_seconds=args.timeout_seconds)
        result = (create(args.source, args.output, quiesced_copy=args.quiesced_copy, **options)
                  if args.command == "create" else restore(args.bundle, args.output,
                      expected_sha256=args.expected_sha256, **options))
        print(json.dumps(result, sort_keys=True))
    except (SnapshotError, OSError, ValueError, EOFError, tarfile.TarError,
            subprocess.SubprocessError, KeyboardInterrupt) as error:
        code = str(error) if isinstance(error, SnapshotError) else "SNAPSHOT_OPERATION_FAILED"
        print(json.dumps(dict(success=False, error=code)), file=sys.stderr)
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()
