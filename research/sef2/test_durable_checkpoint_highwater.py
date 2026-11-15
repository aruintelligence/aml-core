"""Durable checkpoint replay, restart and multi-verifier adversarial tests."""
import os
import tempfile
import unittest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from durable_checkpoint_highwater import DurableCheckpointHighWater
from pinned_checkpoint import PinnedCheckpoint, issue_checkpoint

class DurableHighWaterTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = os.path.join(self.temp.name, "marks.sqlite")
        self.key = Ed25519PrivateKey.generate()
        self.public = self.key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()

    def verifier(self, generation, sequence, authority_id="tenant-a"):
        envelope = issue_checkpoint(self.key, authority_id, generation, sequence)
        return PinnedCheckpoint(lambda: envelope, self.public, authority_id,
                                DurableCheckpointHighWater(self.path))

    def test_restart_cannot_accept_older_signed_checkpoint(self):
        self.assertEqual(self.verifier(8, 4)(), 8)
        with self.assertRaises(ValueError):
            self.verifier(7, 3)()

    def test_same_sequence_conflicting_generation_rejected_after_restart(self):
        self.assertEqual(self.verifier(8, 4)(), 8)
        with self.assertRaises(ValueError):
            self.verifier(9, 4)()

    def test_newer_generation_persists(self):
        self.assertEqual(self.verifier(8, 4)(), 8)
        self.assertEqual(self.verifier(9, 5)(), 9)
        with self.assertRaises(ValueError):
            self.verifier(8, 4)()

    def test_independent_authority_namespaces(self):
        self.assertEqual(self.verifier(8, 4, "tenant-a")(), 8)
        self.assertEqual(self.verifier(2, 1, "tenant-b")(), 2)

    def test_invalid_store_input_rejected(self):
        store = DurableCheckpointHighWater(self.path)
        for sequence, generation in ((True, 1), (-1, 1), (1, True), (1, -1)):
            with self.assertRaises(ValueError):
                store.observe("tenant-a", sequence, generation)

    def test_repeated_identical_checkpoint_is_idempotent(self):
        self.assertEqual(self.verifier(8, 4)(), 8)
        self.assertEqual(self.verifier(8, 4)(), 8)

if __name__ == "__main__":
    unittest.main()
