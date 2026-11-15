"""Durable checkpoint replay, restart and multi-verifier adversarial tests."""
import os
import sqlite3
import tempfile
from concurrent.futures import ThreadPoolExecutor
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

    def test_enrolled_authority_rejects_missing_row_after_restart(self):
        bootstrap = DurableCheckpointHighWater(self.path)
        self.assertTrue(bootstrap.enroll("tenant-a", 3, 5))
        protected = DurableCheckpointHighWater(
            self.path, require_existing=True, require_enrolled=True)
        self.assertEqual(protected.observe("tenant-a", 4, 6), 6)
        with sqlite3.connect(self.path) as db:
            db.execute("DELETE FROM checkpoint_marks WHERE authority_id=?", ("tenant-a",))
        restarted = DurableCheckpointHighWater(
            self.path, require_existing=True, require_enrolled=True)
        with self.assertRaises(ValueError):
            restarted.observe("tenant-a", 5, 7)

    def test_duplicate_enrollment_is_rejected(self):
        store = DurableCheckpointHighWater(self.path)
        self.assertTrue(store.enroll("tenant-a", 0, 0))
        with self.assertRaises(ValueError):
            store.enroll("tenant-a", 0, 0)

    def test_unenrolled_authority_denied(self):
        store = DurableCheckpointHighWater(self.path, require_enrolled=True)
        with self.assertRaises(ValueError):
            store.observe("tenant-a", 1, 1)

    def test_protected_verifier_requires_durable_store(self):
        envelope = issue_checkpoint(self.key, "tenant-a", 5, 2)
        with self.assertRaises(ValueError):
            PinnedCheckpoint(lambda: envelope, self.public, "tenant-a",
                             require_durable=True)
        store = DurableCheckpointHighWater(self.path)
        verifier = PinnedCheckpoint(lambda: envelope, self.public, "tenant-a",
                                    durable_store=store, require_durable=True)
        self.assertEqual(verifier(), 5)

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

    def test_strict_startup_rejects_existing_empty_database_file(self):
        with open(self.path, "wb"):
            pass
        with self.assertRaises(ValueError):
            DurableCheckpointHighWater(self.path, require_existing=True)

    def test_strict_startup_rejects_deleted_checkpoint_database(self):
        with self.assertRaises(ValueError):
            DurableCheckpointHighWater(self.path, require_existing=True)
        store = DurableCheckpointHighWater(self.path)
        self.assertEqual(store.observe("tenant-a", 5, 5), 5)
        self.assertIsInstance(DurableCheckpointHighWater(self.path, require_existing=True),
                              DurableCheckpointHighWater)
        os.unlink(self.path)
        with self.assertRaises(ValueError):
            DurableCheckpointHighWater(self.path, require_existing=True)

    def test_restart_rejects_missing_checkpoint_table(self):
        store = DurableCheckpointHighWater(self.path)
        self.assertEqual(store.observe("tenant-a", 5, 5), 5)
        with sqlite3.connect(self.path) as db:
            db.execute("DROP TABLE checkpoint_marks")
            db.execute("CREATE TABLE unrelated (value INTEGER)")
        with self.assertRaises(ValueError):
            DurableCheckpointHighWater(self.path)

    def test_invalid_store_input_rejected(self):
        store = DurableCheckpointHighWater(self.path)
        for sequence, generation in ((True, 1), (-1, 1), (1, True), (1, -1)):
            with self.assertRaises(ValueError):
                store.observe("tenant-a", sequence, generation)

    def test_concurrent_conflicting_observations_cannot_regress(self):
        store = DurableCheckpointHighWater(self.path)
        self.assertEqual(store.observe("tenant-a", 10, 10), 10)
        def attempt(i):
            try:
                return store.observe("tenant-a", i, i)
            except ValueError:
                return "DENIED"
        with ThreadPoolExecutor(max_workers=12) as pool:
            results = list(pool.map(attempt, range(1, 21)))
        self.assertIn(20, results)
        self.assertEqual(store.observe("tenant-a", 20, 20), 20)
        with self.assertRaises(ValueError):
            store.observe("tenant-a", 19, 19)

    def test_repeated_identical_checkpoint_is_idempotent(self):
        self.assertEqual(self.verifier(8, 4)(), 8)
        self.assertEqual(self.verifier(8, 4)(), 8)

if __name__ == "__main__":
    unittest.main()
