"""Adversarial tests for externally pinned reservation receipt chain."""
import unittest
from reservation_receipt_chain import (
    GENESIS, reservation_chain_hash, verify_reservation_chain,
)

class ReservationReceiptChainTests(unittest.TestCase):
    def setUp(self):
        self.first = ("authority-a", "op-1", "a" * 64, 1)
        self.second = ("authority-a", "op-2", "b" * 64, 2)
        self.head1 = reservation_chain_hash(GENESIS, *self.first)
        self.head2 = reservation_chain_hash(self.head1, *self.second)

    def test_valid_chain_matches_external_head_and_count(self):
        self.assertTrue(verify_reservation_chain(
            [self.first, self.second], self.head2, 2))

    def test_full_rollback_rejected_against_external_head(self):
        self.assertFalse(verify_reservation_chain(
            [self.first], self.head2, 2))

    def test_truncated_chain_rejected_even_if_head_matches_prefix(self):
        self.assertFalse(verify_reservation_chain(
            [self.first], self.head1, 2))

    def test_mutation_rejected(self):
        tampered = ("authority-a", "op-2", "c" * 64, 2)
        self.assertFalse(verify_reservation_chain(
            [self.first, tampered], self.head2, 2))

    def test_reordering_rejected(self):
        self.assertFalse(verify_reservation_chain(
            [self.second, self.first], self.head2, 2))

    def test_invalid_inputs_rejected(self):
        self.assertFalse(verify_reservation_chain([self.first], "bad", 1))
        self.assertFalse(verify_reservation_chain([self.first], self.head1, True))
        self.assertFalse(verify_reservation_chain([("a", "bad\\n", "a" * 64, 1)], self.head1, 1))

    def test_genesis_empty_chain(self):
        self.assertTrue(verify_reservation_chain([], GENESIS, 0))
        self.assertFalse(verify_reservation_chain([], self.head1, 1))

if __name__ == "__main__":
    unittest.main()
