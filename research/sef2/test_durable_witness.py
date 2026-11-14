import concurrent.futures
import os
import tempfile
import unittest
from durable_witness import DurablePinnedWitness
from witness_chain import append

class DurableWitnessTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = os.path.join(self.tmp.name, "witness.db")
        self.w = DurablePinnedWitness(self.path)
        self.one = [append([], "a" * 64)]
        self.two = self.one + [append(self.one, "b" * 64)]

    def test_restart_preserves_checkpoint(self):
        self.assertEqual(self.w.observe(self.two), "ADVANCED")
        restarted = DurablePinnedWitness(self.path)
        self.assertEqual(restarted.pinned()["size"], 2)
        self.assertEqual(restarted.observe(self.one), "ROLLBACK_OR_FORK")

    def test_longer_divergent_history_rejected_after_restart(self):
        self.w.observe(self.one)
        fork = [append([], "c" * 64)]
        fork.append(append(fork, "d" * 64))
        self.assertEqual(DurablePinnedWitness(self.path).observe(fork), "ROLLBACK_OR_FORK")

    def test_concurrent_competing_histories_cannot_both_advance(self):
        fork = [append([], "c" * 64)]
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(self.w.observe, (self.one, fork)))
        self.assertEqual(sorted(results), ["ADVANCED", "ROLLBACK_OR_FORK"])
        self.assertEqual(self.w.pinned()["size"], 1)

    def test_extension_after_restart(self):
        self.w.observe(self.one)
        self.assertEqual(DurablePinnedWitness(self.path).observe(self.two), "ADVANCED")
        self.assertEqual(self.w.pinned()["size"], 2)

    def test_invalid_chain_never_changes_pin(self):
        self.w.observe(self.one)
        self.assertEqual(self.w.observe([{"invalid": True}]), "INVALID_CHAIN")
        self.assertEqual(self.w.pinned()["size"], 1)

    def test_empty_genesis_is_valid(self):
        self.assertEqual(self.w.observe([]), "ADVANCED")
        self.assertEqual(self.w.pinned()["size"], 0)
        self.assertEqual(self.w.observe(self.one), "ADVANCED")
