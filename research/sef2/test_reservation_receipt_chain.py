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

    def test_duplicate_operation_identity_rejected_even_with_matching_hash(self):
        duplicate_head = reservation_chain_hash(self.head1, *self.first)
        self.assertFalse(verify_reservation_chain(
            [self.first, self.first], duplicate_head, 2))

    def test_malformed_external_head_rejected(self):
        self.assertFalse(verify_reservation_chain([self.first], "G" * 64, 1))
        self.assertFalse(verify_reservation_chain([self.first], "A" * 64, 1))

    def test_one_thousand_deterministic_tamper_cases(self):
        """1,000 independent attack variations across four mutation families."""
        for i in range(250):
            original = ("authority-a", "op-%03d" % i, "%064x" % (i + 1), i)
            head = reservation_chain_hash(GENESIS, *original)
            variants = (
                ("authority-b", original[1], original[2], original[3]),
                (original[0], "replayed-%03d" % i, original[2], original[3]),
                (original[0], original[1], "%064x" % (i + 251), original[3]),
                (original[0], original[1], original[2], original[3] + 1),
            )
            self.assertTrue(verify_reservation_chain([original], head, 1))
            for family, modified in enumerate(variants):
                with self.subTest(case=i * 4 + family, family=family):
                    self.assertFalse(verify_reservation_chain([modified], head, 1))

    def test_thousand_record_chain_and_prefix_rollbacks(self):
        """An independently pinned final head rejects every earlier prefix."""
        records = []
        heads = [GENESIS]
        for i in range(1000):
            record = ("authority-a", "operation-%04d" % i,
                      "%064x" % (i + 1), i)
            records.append(record)
            heads.append(reservation_chain_hash(heads[-1], *record))
        self.assertTrue(verify_reservation_chain(records, heads[-1], 1000))
        for length in (0, 1, 2, 10, 100, 250, 500, 750, 999):
            with self.subTest(prefix=length):
                self.assertFalse(verify_reservation_chain(
                    records[:length], heads[-1], 1000))

    def test_genesis_empty_chain(self):
        self.assertTrue(verify_reservation_chain([], GENESIS, 0))
        self.assertFalse(verify_reservation_chain([], self.head1, 1))

if __name__ == "__main__":
    unittest.main()
