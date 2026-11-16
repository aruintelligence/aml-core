import copy
import unittest
from witness_chain import append, verify, checkpoint, fork_detected

class WitnessChainTests(unittest.TestCase):
    def setUp(self):
        self.chain = []
        for d in ("a" * 64, "b" * 64, "c" * 64):
            self.chain.append(append(self.chain, d))

    def test_valid_chain_and_checkpoint(self):
        self.assertTrue(verify(self.chain))
        self.assertTrue(verify(self.chain, checkpoint(self.chain)))

    def test_mutation_rejected(self):
        changed = copy.deepcopy(self.chain)
        changed[1]["receipt_sha256"] = "d" * 64
        self.assertFalse(verify(changed))

    def test_deletion_rejected_with_trusted_checkpoint(self):
        self.assertTrue(verify(self.chain[:-1]))
        self.assertFalse(verify(self.chain[:-1], checkpoint(self.chain)))

    def test_reorder_rejected(self):
        changed = copy.deepcopy(self.chain)
        changed[0], changed[1] = changed[1], changed[0]
        self.assertFalse(verify(changed))

    def test_divergent_heads_detected(self):
        left = checkpoint(self.chain)
        alt = self.chain[:2]
        alt.append(append(alt, "d" * 64))
        self.assertTrue(verify(alt))
        self.assertTrue(fork_detected(left, checkpoint(alt)))

    def test_same_prefix_checkpoint_allows_append(self):
        old = checkpoint(self.chain[:2])
        self.assertTrue(verify(self.chain, old))

    def test_duplicate_receipts_not_prevented(self):
        duplicate = append(self.chain, "c" * 64)
        self.assertTrue(verify(self.chain + [duplicate]))
        self.assertEqual(duplicate["receipt_sha256"], self.chain[-1]["receipt_sha256"])

    def test_invalid_digest_rejected(self):
        with self.assertRaises(ValueError):
            append(self.chain, "not-a-digest")
