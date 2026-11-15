"""Synthetic committed-ledger to witness bridge tests."""
import os
import tempfile
import unittest

from atomic_receipt_reservations import AtomicReceiptReservations
from committed_witness_bridge import advance_from_committed_evidence
from durable_receipt_witness import DurableReceiptWitness
from reservation_receipt_chain import GENESIS

class CommittedWitnessBridgeTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.ledger = AtomicReceiptReservations(
            os.path.join(self.tmp.name, "ledger.db"), "authority")
        self.witness = DurableReceiptWitness(
            os.path.join(self.tmp.name, "witness.db"), "authority")
        self.assertTrue(self.witness.observe(0, GENESIS, 0, GENESIS))

    def test_committed_record_advances(self):
        self.assertTrue(self.ledger.reserve("op-1", "a" * 64, 1))
        self.assertTrue(advance_from_committed_evidence(self.witness, self.ledger))
        self.assertEqual(self.witness.inspect(), self.ledger.evidence()[0])

    def test_no_committed_record_denied(self):
        self.assertFalse(advance_from_committed_evidence(self.witness, self.ledger))

    def test_unwitnessed_gap_denied(self):
        self.assertTrue(self.ledger.reserve("op-1", "a" * 64, 1))
        self.assertTrue(self.ledger.reserve("op-2", "b" * 64, 1))
        self.assertFalse(advance_from_committed_evidence(self.witness, self.ledger))

    def test_stale_witness_replay_denied(self):
        self.assertTrue(self.ledger.reserve("op-1", "a" * 64, 1))
        self.assertTrue(advance_from_committed_evidence(self.witness, self.ledger))
        self.assertFalse(advance_from_committed_evidence(self.witness, self.ledger))

    def test_foreign_authority_denied(self):
        other = DurableReceiptWitness(os.path.join(self.tmp.name, "foreign.db"), "foreign")
        self.assertTrue(other.observe(0, GENESIS, 0, GENESIS))
        self.assertTrue(self.ledger.reserve("op-1", "a" * 64, 1))
        self.assertFalse(advance_from_committed_evidence(other, self.ledger))

    def test_mutated_ledger_denied(self):
        import sqlite3
        self.assertTrue(self.ledger.reserve("op-1", "a" * 64, 1))
        with sqlite3.connect(self.ledger.path) as db:
            db.execute("UPDATE receipt_reservations SET digest=? WHERE sequence=1", ("f" * 64,))
        self.assertFalse(advance_from_committed_evidence(self.witness, self.ledger))

if __name__ == "__main__":
    unittest.main()
