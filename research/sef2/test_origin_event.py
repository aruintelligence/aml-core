import concurrent.futures
import os
import tempfile
import unittest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from origin_event import OriginVerifier, issue_origin

class OriginEventTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = os.path.join(self.tmp.name, "seen.db")
        self.key = Ed25519PrivateKey.generate()
        self.verifier = OriginVerifier(self.path, {"provider-fixture": self.key.public_key()})
        self.effect = {"effect_id": "effect-1", "kind": "synthetic-only"}

    def receipt(self, key=None, sequence=1, op="op-1", effect=None):
        return issue_origin(key or self.key, "provider-fixture", sequence, op, "a"*64,
            self.effect if effect is None else effect)

    def test_pinned_key_accepts_once(self):
        receipt = self.receipt()
        self.assertEqual(self.verifier.accept(receipt), "AUTHENTICATED_SYNTHETIC_EVENT")
        self.assertEqual(self.verifier.accept(receipt), "REPLAY_OR_DUPLICATE")

    def test_restart_retains_replay_ledger(self):
        self.verifier.accept(self.receipt())
        restarted = OriginVerifier(self.path, {"provider-fixture": self.key.public_key()})
        self.assertEqual(restarted.accept(self.receipt()), "REPLAY_OR_DUPLICATE")

    def test_unknown_provider_fails_closed(self):
        self.assertEqual(OriginVerifier(os.path.join(self.tmp.name, "other.db"), {}).accept(self.receipt()), "UNTRUSTED_PROVIDER")

    def test_key_substitution_rejected(self):
        self.assertEqual(self.verifier.accept(self.receipt(key=Ed25519PrivateKey.generate())), "INVALID_SIGNATURE")

    def test_tampered_effect_rejected(self):
        receipt = self.receipt()
        receipt["event"]["synthetic_effect"]["effect_id"] = "forged"
        self.assertEqual(self.verifier.accept(receipt), "INVALID_SIGNATURE")

    def test_sequence_reuse_rejected(self):
        self.verifier.accept(self.receipt())
        self.assertEqual(self.verifier.accept(self.receipt(sequence=1, op="op-2")), "REPLAY_OR_DUPLICATE")

    def test_operation_reuse_rejected(self):
        self.verifier.accept(self.receipt())
        self.assertEqual(self.verifier.accept(self.receipt(sequence=2)), "REPLAY_OR_DUPLICATE")

    def test_concurrent_replay_only_one_accepted(self):
        receipt = self.receipt()
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(self.verifier.accept, [receipt]*8))
        self.assertEqual(results.count("AUTHENTICATED_SYNTHETIC_EVENT"), 1)
        self.assertEqual(results.count("REPLAY_OR_DUPLICATE"), 7)

    def test_non_synthetic_event_cannot_be_issued(self):
        with self.assertRaises(ValueError):
            self.receipt(effect={"effect_id": "effect-1", "kind": "payment"})

    def test_boolean_sequence_not_integer(self):
        with self.assertRaises(ValueError):
            self.receipt(sequence=True)

    def test_wrong_signature_format(self):
        receipt = self.receipt()
        receipt["signature"] = "not-hex"
        self.assertEqual(self.verifier.accept(receipt), "INVALID_SIGNATURE")
