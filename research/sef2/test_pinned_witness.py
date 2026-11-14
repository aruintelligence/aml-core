import unittest
from witness_chain import append
from pinned_witness import PinnedWitness

class PinnedWitnessTests(unittest.TestCase):
    def setUp(self):
        self.w = PinnedWitness()
        self.chain = [append([], "a" * 64)]

    def test_first_observation_and_repeat(self):
        self.assertEqual(self.w.observe(self.chain), "ADVANCED")
        self.assertEqual(self.w.observe(self.chain), "UNCHANGED")

    def test_valid_extension_advances(self):
        self.assertEqual(self.w.observe(self.chain), "ADVANCED")
        extended = self.chain + [append(self.chain, "b" * 64)]
        self.assertEqual(self.w.observe(extended), "ADVANCED")
        self.assertEqual(self.w.pinned()["size"], 2)

    def test_truncation_denied(self):
        self.w.observe(self.chain)
        self.assertEqual(self.w.observe([]), "ROLLBACK_OR_FORK")
        self.assertEqual(self.w.pinned()["size"], 1)

    def test_same_size_fork_denied(self):
        self.w.observe(self.chain)
        fork = [append([], "b" * 64)]
        self.assertEqual(self.w.observe(fork), "ROLLBACK_OR_FORK")

    def test_longer_fork_denied(self):
        self.w.observe(self.chain)
        fork = [append([], "b" * 64)]
        fork.append(append(fork, "c" * 64))
        self.assertEqual(self.w.observe(fork), "ROLLBACK_OR_FORK")

    def test_checkpoint_snapshot_is_not_mutable_alias(self):
        self.w.observe(self.chain)
        snapshot = self.w.pinned()
        snapshot["head"] = "0" * 64
        self.assertNotEqual(self.w.pinned()["head"], snapshot["head"])

    def test_invalid_chain_does_not_advance(self):
        self.w.observe(self.chain)
        invalid = [{"hash": "a"}]
        self.assertEqual(self.w.observe(invalid), "INVALID_CHAIN")
        self.assertEqual(self.w.pinned()["size"], 1)
