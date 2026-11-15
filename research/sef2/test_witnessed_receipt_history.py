"""Witness checkpoint mismatch and rollback classification tests."""
import unittest
from reservation_receipt_chain import GENESIS, reservation_chain_hash
from witnessed_receipt_history import classify_witnessed_history

class WitnessedReceiptHistoryTests(unittest.TestCase):
    def setUp(self):
        self.one = ("authority", "op-1", "a" * 64, 1)
        self.two = ("authority", "op-2", "b" * 64, 2)
        self.h1 = reservation_chain_hash(GENESIS, *self.one)
        self.h2 = reservation_chain_hash(self.h1, *self.two)

    def test_match(self):
        self.assertEqual(classify_witnessed_history(
            [self.one, self.two], (2, self.h2), (2, self.h2)), "MATCH")

    def test_rollback_behind_witness(self):
        self.assertEqual(classify_witnessed_history(
            [self.one], (1, self.h1), (2, self.h2)), "BEHIND")

    def test_fork_same_sequence(self):
        self.assertEqual(classify_witnessed_history(
            [self.one], (1, self.h1), (1, "f" * 64)), "DIVERGED")

    def test_unanchored_tail_is_not_match(self):
        self.assertEqual(classify_witnessed_history(
            [self.one, self.two], (2, self.h2), (1, self.h1)), "AHEAD_UNANCHORED")

    def test_forked_prefix_is_diverged(self):
        self.assertEqual(classify_witnessed_history(
            [self.one, self.two], (2, self.h2), (1, "f" * 64)), "DIVERGED")

    def test_invalid_local_history_is_diverged(self):
        self.assertEqual(classify_witnessed_history(
            [self.one], (2, self.h2), (2, self.h2)), "DIVERGED")

    def test_invalid_witness_shape_unknown(self):
        self.assertEqual(classify_witnessed_history(
            [self.one], (1, self.h1), ("1", self.h1)), "UNKNOWN")

    def test_genesis_witness_with_local_tail(self):
        self.assertEqual(classify_witnessed_history(
            [self.one], (1, self.h1), (0, GENESIS)), "AHEAD_UNANCHORED")

if __name__ == "__main__":
    unittest.main()
