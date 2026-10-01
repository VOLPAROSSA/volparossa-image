#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Real local GnuPG synthetic snapshot proof, not peer storage or an Immich boot."""

import gzip
import hashlib
import importlib.util
import io
import os
from pathlib import Path
import shutil
import stat
import subprocess
import tarfile
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("immich_snapshot", ROOT / "scripts/immich_snapshot.py")
SNAPSHOT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SNAPSHOT)


class SnapshotTests(unittest.TestCase):
    def setUp(self):
        (ROOT / "build").mkdir(exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(prefix="t-", dir=ROOT / "build")
        self.root = Path(self.temporary.name)
        self.source = self.root / "source"
        self.source.mkdir(mode=0o700)
        (self.source / "database.sql.gz").write_bytes(gzip.compress(
            b"-- synthetic fixture, not an Immich schema\nCREATE TABLE lawful_fixture (id integer);\n"))
        for directory in ("upload", "library", "profile", "thumbs", "encoded-video", "backups"):
            (self.source / directory).mkdir()
        (self.source / "library/owner").mkdir()
        (self.source / "library/owner/synthetic.bin").write_bytes(bytes(range(256)) * 8192)
        (self.source / "upload/empty.bin").write_bytes(b"")
        (self.source / "profile/café.txt").write_bytes(b"synthetic profile, never a personal photo")
        self.bundle = self.root / "bundle"

    def tearDown(self):
        # No private fixture data or owned agent sockets survive any result.
        self.assertFalse(any(path.name.startswith("g-") for path in self.root.iterdir()))
        self.assertFalse(any(path.name.startswith(("s-", "r-")) for path in self.root.iterdir()))
        self.temporary.cleanup()

    def create(self):
        return SNAPSHOT.create(self.source, self.bundle, quiesced_copy=True, timeout_seconds=20)

    def restore(self, receipt, name="restored"):
        return SNAPSHOT.restore(self.bundle, self.root / name,
            expected_sha256=receipt["cipher_sha256"], timeout_seconds=20)

    def test_real_encrypted_snapshot_two_nondestructive_restores(self):
        original = {str(p.relative_to(self.source)): p.read_bytes()
                    for p in self.source.rglob("*") if p.is_file()}
        receipt = self.create()
        self.assertEqual(receipt["encryption"], "OpenPGP-AES256")
        self.assertEqual(set(p.name for p in self.bundle.iterdir()),
                         {"snapshot.pgp", "recovery.key", "receipt.json"})
        cipher = (self.bundle / "snapshot.pgp").read_bytes()
        self.assertNotIn(b"synthetic profile", cipher)
        self.assertNotIn(b"library/owner/synthetic.bin", cipher)
        self.assertEqual(hashlib.sha256(cipher).hexdigest(), receipt["cipher_sha256"])
        self.assertEqual(stat.S_IMODE(self.bundle.stat().st_mode), 0o700)
        self.assertTrue(all(stat.S_IMODE(p.stat().st_mode) == 0o600 for p in self.bundle.iterdir()))
        for name in ("first", "second"):
            report = self.restore(receipt, name)
            self.assertTrue(report["manifest_verified"] and report["openpgp_integrity_verified"])
            restored = {str(p.relative_to(self.root / name)): p.read_bytes()
                        for p in (self.root / name).rglob("*") if p.is_file()}
            self.assertEqual(original, restored)
        self.assertEqual((self.bundle / "snapshot.pgp").read_bytes(), cipher)
        self.assertTrue((self.source / "library/owner/synthetic.bin").exists())

    def test_wrong_key_and_corruption_do_not_publish(self):
        receipt = self.create()
        key = (self.bundle / "recovery.key").read_bytes()
        (self.bundle / "recovery.key").write_bytes(b"0" * 64 + b"\n")
        with self.assertRaises((SNAPSHOT.SnapshotError, BrokenPipeError)):
            self.restore(receipt, "wrong-key")
        self.assertFalse((self.root / "wrong-key").exists())
        (self.bundle / "recovery.key").write_bytes(key)
        cipher = bytearray((self.bundle / "snapshot.pgp").read_bytes())
        cipher[-10] ^= 1
        (self.bundle / "snapshot.pgp").write_bytes(cipher)
        with self.assertRaisesRegex(SNAPSHOT.SnapshotError, "CIPHER_HASH_MISMATCH"):
            self.restore(receipt, "wrong-hash")
        self.assertFalse((self.root / "wrong-hash").exists())
        # Even a replaced local receipt/hash cannot turn corrupted OpenPGP into a
        # valid restore: require the real MDC and final GnuPG success as well.
        receipt["cipher_sha256"] = hashlib.sha256(cipher).hexdigest()
        with self.assertRaises(SNAPSHOT.SnapshotError):
            self.restore(receipt, "corrupt-mdc")
        self.assertFalse((self.root / "corrupt-mdc").exists())

    def test_mutation_is_rejected_without_publishing_or_deleting_source(self):
        original = SNAPSHOT.write_tar
        def changed(root_fd, entries, destination):
            original(root_fd, entries, destination)
            (self.source / "upload/added.bin").write_bytes(b"changed during snapshot")
        with patch.object(SNAPSHOT, "write_tar", changed):
            with self.assertRaisesRegex(SNAPSHOT.SnapshotError, "SOURCE_CHANGED"):
                self.create()
        self.assertFalse(self.bundle.exists())
        self.assertTrue((self.source / "upload/added.bin").exists())

    def test_quiescence_live_database_links_bounds_and_overlap_rejected(self):
        with self.assertRaisesRegex(SNAPSHOT.SnapshotError, "QUIESCED_COPY_ACK_REQUIRED"):
            SNAPSHOT.create(self.source, self.bundle)
        with self.assertRaisesRegex(SNAPSHOT.SnapshotError, "OVERLAPPING_INPUT_OUTPUT"):
            SNAPSHOT.create(self.source, self.source / "backup", quiesced_copy=True)
        with self.assertRaisesRegex(SNAPSHOT.SnapshotError, "SOURCE_LIMIT_EXCEEDED"):
            SNAPSHOT.create(self.source, self.bundle, quiesced_copy=True, max_bytes=1024)
        (self.source / "pgdata").mkdir()
        with self.assertRaises(SNAPSHOT.SnapshotError):
            self.create()
        (self.source / "pgdata").rmdir()
        alias = self.source / "upload/link"
        alias.symlink_to(self.source / "database.sql.gz")
        with self.assertRaisesRegex(SNAPSHOT.SnapshotError, "UNSAFE_SOURCE_ENTRY"):
            self.create()
        alias.unlink()
        os.link(self.source / "database.sql.gz", alias)
        with self.assertRaisesRegex(SNAPSHOT.SnapshotError, "UNSAFE_SOURCE_ENTRY"):
            self.create()

    def test_existing_targets_and_untrusted_receipt_are_not_authority(self):
        receipt = self.create()
        existing = self.root / "existing"
        existing.mkdir()
        (existing / "keep").write_bytes(b"preserve")
        with self.assertRaisesRegex(SNAPSHOT.SnapshotError, "OUTPUT_ALREADY_EXISTS"):
            self.restore(receipt, "existing")
        self.assertEqual((existing / "keep").read_bytes(), b"preserve")
        with self.assertRaisesRegex(SNAPSHOT.SnapshotError, "EXPECTED_CIPHER_HASH_REQUIRED"):
            SNAPSHOT.restore(self.bundle, self.root / "missing", expected_sha256="")
        (self.bundle / "receipt.json").write_text('{"cipher_sha256":"not trusted"}')
        self.assertTrue(self.restore(receipt)["restored"])

    def test_output_parent_requires_exact_private_owner_directory(self):
        parent = self.root / "destination"
        parent.mkdir(mode=0o700)
        target = parent / "new-bundle"
        for permissions in (0o755, 0o770, 0o702, 0o2700):
            parent.chmod(permissions)
            with self.assertRaisesRegex(SNAPSHOT.SnapshotError, "UNSAFE_OUTPUT_PARENT"):
                SNAPSHOT.new_target(target, self.source)
            self.assertFalse(target.exists())
        parent.chmod(0o700)
        with patch.object(SNAPSHOT.os, "getuid", return_value=os.getuid() + 1):
            with self.assertRaisesRegex(SNAPSHOT.SnapshotError, "UNSAFE_OUTPUT_PARENT"):
                SNAPSHOT.new_target(target, self.source)
        self.assertEqual(SNAPSHOT.new_target(target, self.source), target)
        self.assertEqual(SNAPSHOT.DEFAULT_BYTES, 60 * 1024**3)

    def test_tar_traversal_links_and_huge_headers_fail_before_extraction(self):
        for name, kind, size in (("data/../escape", tarfile.REGTYPE, 0),
                                 ("data/upload/link", tarfile.SYMTYPE, 0),
                                 ("data/upload/huge", tarfile.REGTYPE, 1000000000),
                                 ("extended", tarfile.XHDTYPE, 1000000000)):
            header = tarfile.TarInfo(name)
            header.type, header.size = kind, size
            output = self.root / "parsed"
            output.mkdir()
            (output / "upload").mkdir()
            try:
                with self.assertRaises(SNAPSHOT.SnapshotError):
                    SNAPSHOT.restore_tar(io.BytesIO(header.tobuf(format=tarfile.USTAR_FORMAT)), output, 1024)
            finally:
                shutil.rmtree(output)
        self.assertFalse((self.root / "escape").exists())

    def test_owned_agent_join_runtime_cleanup_and_no_secret_arguments(self):
        runtime = Path(f"/run/user/{os.getuid()}/gnupg")
        before = set(runtime.iterdir()) if runtime.is_dir() else set()
        original = subprocess.Popen
        children = []
        def launch(command, *args, **kwargs):
            self.assertNotIn("--passphrase", command)
            self.assertNotIn("--passphrase-file", command)
            self.assertTrue(all(not __import__("re").fullmatch(r"[0-9a-f]{64}", str(arg)) for arg in command))
            self.assertNotIn("HOME", kwargs.get("env", {}))
            process = original(command, *args, **kwargs)
            children.append(process)
            return process
        with patch.object(subprocess, "Popen", launch):
            receipt = self.create()
            self.restore(receipt)
        self.assertTrue(children)
        self.assertTrue(all(child.poll() is not None for child in children))
        self.assertEqual(before, set(runtime.iterdir()) if runtime.is_dir() else set())


if __name__ == "__main__":
    unittest.main()
