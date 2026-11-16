"""Fail-closed witnessed history preflight regression suite."""
import os
import tempfile
import unittest
from atomic_receipt_reservations import AtomicReceiptReservations
from durable_receipt_witness import DurableReceiptWitness
from pinned_ledger_witness_bridge import PinnedLedgerWitnessBridge
from reservation_receipt_chain import GENESIS
from witness_integrity_preflight import preflight_witness_integrity

class WitnessIntegrityPreflightTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        path = os.path.join(self.tmp.name, "ledger.db")
        self.ledger = AtomicReceiptReservations(path, "authority")
        self.witness = DurableReceiptWitness(os.path.join(self.tmp.name, "witness.db"), "authority")
        self.assertTrue(self.witness.observe(0, GENESIS, 0, GENESIS))
        self.bridge = PinnedLedgerWitnessBridge(path, "authority", expected_uid=os.getuid())

    def test_matching_history_is_ready(self):
        self.assertEqual(preflight_witness_integrity(self.witness, self.bridge),
                         (True, "WITNESSED_HISTORY_MATCH"))

    def test_unwitnessed_commit_denied(self):
        self.assertTrue(self.ledger.reserve("op-1", "a" * 64, 1))
        self.assertEqual(preflight_witness_integrity(self.witness, self.bridge),
                         (False, "UNWITNESSED_COMMIT"))

    def test_witnessed_commit_ready(self):
        self.assertTrue(self.ledger.reserve("op-1", "a" * 64, 1))
        self.assertTrue(self.bridge.advance(self.witness))
        self.assertEqual(preflight_witness_integrity(self.witness, self.bridge),
                         (True, "WITNESSED_HISTORY_MATCH"))

    def test_ledger_rollback_denied(self):
        import sqlite3
        self.assertTrue(self.ledger.reserve("op-1", "a" * 64, 1))
        self.assertTrue(self.bridge.advance(self.witness))
        with sqlite3.connect(self.bridge.ledger_path) as db:
            db.execute("DELETE FROM receipt_reservations")
            db.execute("UPDATE receipt_head SET sequence=0, chain_hash=?", (GENESIS,))
        self.assertEqual(preflight_witness_integrity(self.witness, self.bridge),
                         (False, "LEDGER_ROLLBACK"))

    def test_missing_ledger_denied(self):
        os.unlink(self.bridge.ledger_path)
        self.assertEqual(preflight_witness_integrity(self.witness, self.bridge),
                         (False, "EVIDENCE_UNAVAILABLE"))

    def test_provider_failure_denied(self):
        class BrokenWitness:
            authority_id = "authority"
            def inspect(self):
                raise RuntimeError("storage unavailable")
        self.assertEqual(preflight_witness_integrity(BrokenWitness(), self.bridge),
                         (False, "EVIDENCE_UNAVAILABLE"))

if __name__ == "__main__":
    unittest.main()
