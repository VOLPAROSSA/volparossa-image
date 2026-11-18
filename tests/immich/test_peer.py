"""Only same-run verified ciphertext can reach a restored Immich instance."""
import hashlib
import os
from pathlib import Path
import tempfile
import unittest

from peer import PeerError, exact_transport, returned_cipher, source_cipher_removed, unique_pairs


class BindingTests(unittest.TestCase):
    def test_binds_run_and_exact_release_and_cleanup(self):
        bindings = dict(core_revision="a" * 40, image_revision="b" * 40, run_id="42",
                        run_attempt="1", cipher_bytes=32, cipher_sha256="c" * 64)
        receipt = dict(version=1, kind="image-immich-peer-transport", **bindings,
                       source_ciphertext_removed=True, withdrawn_provider_unavailable=True,
                       peer_restores=2, all_eight_copies_deleted=True, providers_final_usage_zero=True,
                       kvm_joined=True, guest_private_state_removed=True)
        exact_transport(receipt, bindings)
        for key, other in (("core_revision", "d" * 40), ("image_revision", "e" * 40),
                           ("run_attempt", "2"), ("run_id", "43"), ("cipher_bytes", 33),
                           ("cipher_sha256", "d" * 64), ("peer_restores", 1),
                           ("providers_final_usage_zero", 1), ("guest_private_state_removed", False)):
            with self.subTest(key=key), self.assertRaises(PeerError):
                exact_transport(receipt | {key: other}, bindings)
        with self.assertRaises(PeerError):
            exact_transport(receipt | {"unknown": True}, bindings)
        with self.assertRaises(PeerError):
            unique_pairs([("version", 2), ("version", 1)])

    def test_source_archive_must_be_removed_before_recovery(self):
        with tempfile.TemporaryDirectory() as private:
            folder = Path(private)
            receipt = folder / "receipt.json"
            receipt.touch(mode=0o600)
            (folder / "snapshot.pgp").touch(mode=0o600)
            with self.assertRaises(PeerError):
                source_cipher_removed(folder)
            (folder / "snapshot.pgp").unlink()
            source_cipher_removed(folder)
            receipt.chmod(0o644)
            with self.assertRaises(PeerError):
                source_cipher_removed(folder)

    def test_receiver_has_only_private_exact_independent_file(self):
        with tempfile.TemporaryDirectory() as private:
            root = Path(private)
            folder = root / "receiver"
            folder.mkdir(mode=0o700)
            raw = b"synthetic opaque bytes"
            digest = hashlib.sha256(raw).hexdigest()
            cipher = folder / "snapshot.pgp"
            cipher.write_bytes(raw)
            cipher.chmod(0o600)
            returned_cipher(folder, len(raw), digest)
            for size, sha in ((1, digest), (len(raw), "0" * 64)):
                with self.assertRaises(PeerError):
                    returned_cipher(folder, size, sha)
            os.link(cipher, root / "original")
            with self.assertRaises(PeerError):
                returned_cipher(folder, len(raw), digest)
            cipher.unlink()
            cipher.symlink_to(root / "original")
            with self.assertRaises(OSError):
                returned_cipher(folder, len(raw), digest)
            cipher.unlink()
            cipher.write_bytes(raw)
            (folder / "recovery.key").touch()
            with self.assertRaises(PeerError):
                returned_cipher(folder, len(raw), digest)
