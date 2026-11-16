"""Adversarial tests for signed checkpoint verification and effect gating."""
import os
import tempfile
from concurrent.futures import ThreadPoolExecutor
from threading import Event
import unittest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from effect_authority import EffectAuthority
from pinned_checkpoint import PinnedCheckpoint, issue_checkpoint

def effect():
    return {"operation_id":"op1","kind":"fixture:write","target":"fixture:protected","value":4}

class PinnedCheckpointTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.path = os.path.join(temp.name, "effects.sqlite")
        self.key = Ed25519PrivateKey.generate()
        self.public = self.key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()
        self.envelope = issue_checkpoint(self.key, "authority-a", 4, 1)
        self.fetch = lambda: self.envelope

    def test_signed_checkpoint_gates_effect(self):
        checkpoint = PinnedCheckpoint(self.fetch, self.public, "authority-a")
        authority = EffectAuthority(self.path, lambda *args: True, checkpoint)
        self.assertEqual(authority.commit(effect(), 4), "DENIED")
        self.assertTrue(authority.advance_policy_floor(4))
        self.assertEqual(authority.commit(effect(), 4), "APPLIED")

    def test_signature_tampering_fails_closed(self):
        checkpoint = PinnedCheckpoint(self.fetch, self.public, "authority-a")
        self.envelope["payload"]["generation"] = 0
        authority = EffectAuthority(self.path, lambda *args: True, checkpoint)
        self.assertEqual(authority.commit(effect(), 4), "DENIED")

    def test_cross_authority_replay_fails_closed(self):
        checkpoint = PinnedCheckpoint(self.fetch, self.public, "authority-b")
        authority = EffectAuthority(self.path, lambda *args: True, checkpoint)
        self.assertEqual(authority.commit(effect(), 4), "DENIED")

    def test_wrong_signing_key_fails_closed(self):
        wrong = Ed25519PrivateKey.generate()
        self.envelope = issue_checkpoint(wrong, "authority-a", 4, 1)
        checkpoint = PinnedCheckpoint(self.fetch, self.public, "authority-a")
        authority = EffectAuthority(self.path, lambda *args: True, checkpoint)
        self.assertEqual(authority.commit(effect(), 4), "DENIED")

    def test_observed_checkpoint_rollback_rejected(self):
        checkpoint = PinnedCheckpoint(self.fetch, self.public, "authority-a")
        self.assertEqual(checkpoint(), 4)
        self.envelope = issue_checkpoint(self.key, "authority-a", 3, 0)
        with self.assertRaises(ValueError):
            checkpoint()

    def test_same_sequence_conflicting_generation_rejected(self):
        checkpoint = PinnedCheckpoint(self.fetch, self.public, "authority-a")
        self.assertEqual(checkpoint(), 4)
        self.envelope = issue_checkpoint(self.key, "authority-a", 5, 1)
        with self.assertRaises(ValueError):
            checkpoint()

    def test_newer_signed_checkpoint_accepted(self):
        checkpoint = PinnedCheckpoint(self.fetch, self.public, "authority-a")
        self.assertEqual(checkpoint(), 4)
        self.envelope = issue_checkpoint(self.key, "authority-a", 5, 2)
        self.assertEqual(checkpoint(), 5)

    def test_concurrent_fetches_cannot_regress_high_water(self):
        entered = Event()
        release = Event()
        older = issue_checkpoint(self.key, "authority-a", 4, 1)
        newer = issue_checkpoint(self.key, "authority-a", 5, 2)
        calls = [0]
        def fetch():
            calls[0] += 1
            if calls[0] == 1:
                entered.set()
                if not release.wait(timeout=5):
                    raise RuntimeError("test synchronization timed out")
                return older
            return newer
        checkpoint = PinnedCheckpoint(fetch, self.public, "authority-a")
        with ThreadPoolExecutor(max_workers=2) as pool:
            first = pool.submit(checkpoint)
            self.assertTrue(entered.wait(timeout=5))
            second = pool.submit(checkpoint)
            release.set()
            self.assertEqual(first.result(timeout=10), 4)
            self.assertEqual(second.result(timeout=10), 5)
        self.assertEqual(checkpoint.last_sequence, 2)
        self.assertEqual(checkpoint.last_generation, 5)

    def test_malformed_checkpoint_fails_closed(self):
        self.envelope = {"payload": [], "signature": "zz"}
        checkpoint = PinnedCheckpoint(self.fetch, self.public, "authority-a")
        authority = EffectAuthority(self.path, lambda *args: True, checkpoint)
        self.assertEqual(authority.commit(effect(), 4), "DENIED")

if __name__ == "__main__":
    unittest.main()
