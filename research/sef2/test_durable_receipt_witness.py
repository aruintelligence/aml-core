"""Monotonic witness compare-and-swap research tests."""
import os
import tempfile
import unittest
from durable_receipt_witness import DurableReceiptWitness
from reservation_receipt_chain import GENESIS, reservation_chain_hash

class DurableReceiptWitnessTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = os.path.join(self.temp.name, "witness.sqlite")
        self.store = DurableReceiptWitness(self.path, "authority")
        self.first = ("authority", "op-1", "a" * 64, 1)
        self.h1 = reservation_chain_hash(GENESIS, *self.first)

    def test_initialize_then_advance(self):
        self.assertTrue(self.store.observe(0, GENESIS, 0, GENESIS))
        self.assertTrue(self.store.observe(1, self.h1, 0, GENESIS, self.first))
        self.assertEqual(self.store.inspect(), (1, self.h1))

    def test_stale_cas_rejected(self):
        self.assertTrue(self.store.observe(0, GENESIS, 0, GENESIS))
        self.assertTrue(self.store.observe(1, self.h1, 0, GENESIS, self.first))
        self.assertFalse(self.store.observe(1, self.h1, 0, GENESIS))
        self.assertEqual(self.store.inspect(), (1, self.h1))

    def test_skipped_generation_rejected(self):
        self.assertTrue(self.store.observe(0, GENESIS, 0, GENESIS))
        self.assertFalse(self.store.observe(2, self.h1, 0, GENESIS))

    def test_restart_keeps_high_water(self):
        self.assertTrue(self.store.observe(0, GENESIS, 0, GENESIS))
        self.assertTrue(self.store.observe(1, self.h1, 0, GENESIS))
        reopened = DurableReceiptWitness(self.path, "authority", require_existing=True)
        self.assertEqual(reopened.inspect(), (1, self.h1))
        self.assertFalse(reopened.observe(1, self.h1, 0, GENESIS, self.first))

    def test_invented_checkpoint_rejected(self):
        self.assertTrue(self.store.observe(0, GENESIS, 0, GENESIS))
        self.assertFalse(self.store.observe(1, "f" * 64, 0, GENESIS, self.first))
        self.assertFalse(self.store.observe(1, self.h1, 0, GENESIS))
        self.assertEqual(self.store.inspect(), (0, GENESIS))

    def test_invalid_checkpoint_denied(self):
        self.assertFalse(self.store.observe(True, GENESIS, 0, GENESIS))
        self.assertFalse(self.store.observe(0, "bad", 0, GENESIS))
        self.assertFalse(self.store.observe(0, GENESIS, 0, "Z" * 64))

if __name__ == "__main__":
    unittest.main()
