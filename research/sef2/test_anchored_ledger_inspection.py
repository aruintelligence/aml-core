"""Anchored inspection detects internally consistent whole-ledger rollback."""
import os
import shutil
import tempfile
import unittest

from anchored_ledger_inspection import inspect_anchored_ledger, anchored_ledger_is_current
from atomic_receipt_reservations import AtomicReceiptReservations
from durable_receipt_witness import DurableReceiptWitness
from pinned_ledger_witness_bridge import PinnedLedgerWitnessBridge
from reservation_receipt_chain import GENESIS

class AnchoredLedgerInspectionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = os.path.join(self.tmp.name, "ledger.db")
        self.ledger = AtomicReceiptReservations(self.path, "authority")
        self.witness = DurableReceiptWitness(os.path.join(self.tmp.name, "witness.db"), "authority")
        self.assertTrue(self.witness.observe(0, GENESIS, 0, GENESIS))
        self.bridge = PinnedLedgerWitnessBridge(self.path, "authority", expected_uid=os.getuid())

    def test_matching_committed_head(self):
        self.assertTrue(self.ledger.reserve("op-1", "a" * 64, 1))
        self.assertTrue(self.bridge.advance(self.witness))
        self.assertEqual(inspect_anchored_ledger(self.witness, self.bridge), "MATCH")
        self.assertTrue(anchored_ledger_is_current(self.witness, self.bridge))

    def test_unwitnessed_append_not_current(self):
        self.assertTrue(self.ledger.reserve("op-1", "a" * 64, 1))
        self.assertEqual(inspect_anchored_ledger(self.witness, self.bridge), "AHEAD_UNANCHORED")
        self.assertFalse(anchored_ledger_is_current(self.witness, self.bridge))

    def test_consistent_rollback_is_detected(self):
        self.assertTrue(self.ledger.reserve("op-1", "a" * 64, 1))
        self.assertTrue(self.bridge.advance(self.witness))
        # Roll back the same inode by deleting records and restoring genesis.
        import sqlite3
        with sqlite3.connect(self.path) as db:
            db.execute("DELETE FROM receipt_reservations")
            db.execute("UPDATE receipt_head SET sequence=0, chain_hash=?", (GENESIS,))
        self.assertEqual(inspect_anchored_ledger(self.witness, self.bridge), "BEHIND")
        self.assertFalse(anchored_ledger_is_current(self.witness, self.bridge))

    def test_replaced_ledger_is_unknown(self):
        os.unlink(self.path)
        AtomicReceiptReservations(self.path, "authority")
        self.assertEqual(inspect_anchored_ledger(self.witness, self.bridge), "UNKNOWN")

    def test_foreign_witness_is_unknown(self):
        foreign = DurableReceiptWitness(os.path.join(self.tmp.name, "foreign.db"), "foreign")
        self.assertTrue(foreign.observe(0, GENESIS, 0, GENESIS))
        self.assertEqual(inspect_anchored_ledger(foreign, self.bridge), "UNKNOWN")

if __name__ == "__main__":
    unittest.main()
