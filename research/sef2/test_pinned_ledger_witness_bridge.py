"""Pinned committed-ledger witness source adversarial tests."""
import os
import tempfile
import unittest
from atomic_receipt_reservations import AtomicReceiptReservations
from durable_receipt_witness import DurableReceiptWitness
from pinned_ledger_witness_bridge import PinnedLedgerWitnessBridge
from reservation_receipt_chain import GENESIS

class PinnedLedgerWitnessBridgeTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = os.path.join(self.tmp.name, "ledger.db")
        self.ledger = AtomicReceiptReservations(self.path, "authority")
        self.witness = DurableReceiptWitness(os.path.join(self.tmp.name, "witness.db"), "authority")
        self.assertTrue(self.witness.observe(0, GENESIS, 0, GENESIS))
        self.bridge = PinnedLedgerWitnessBridge(self.path, "authority", expected_uid=os.getuid())

    def test_committed_advance(self):
        self.assertTrue(self.ledger.reserve("op-1", "a" * 64, 1))
        self.assertTrue(self.bridge.advance(self.witness))

    def test_missing_ledger_rejected(self):
        os.unlink(self.path)
        self.assertFalse(self.bridge.advance(self.witness))

    def test_replaced_ledger_rejected(self):
        os.unlink(self.path)
        AtomicReceiptReservations(self.path, "authority")
        self.assertFalse(self.bridge.advance(self.witness))

    def test_symlink_replacement_rejected(self):
        original = self.path + ".original"
        os.rename(self.path, original)
        os.symlink(original, self.path)
        self.assertFalse(self.bridge.advance(self.witness))

    def test_wrong_expected_owner_rejected(self):
        with self.assertRaises(ValueError):
            PinnedLedgerWitnessBridge(self.path, "authority", expected_uid=os.getuid() + 1)

    def test_wrong_witness_authority_rejected(self):
        foreign = DurableReceiptWitness(os.path.join(self.tmp.name, "foreign.db"), "foreign")
        self.assertTrue(foreign.observe(0, GENESIS, 0, GENESIS))
        self.assertTrue(self.ledger.reserve("op-1", "a" * 64, 1))
        self.assertFalse(self.bridge.advance(foreign))

if __name__ == "__main__":
    unittest.main()
