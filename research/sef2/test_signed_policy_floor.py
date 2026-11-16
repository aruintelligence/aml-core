"""Adversarial signed policy-floor verification and revocation tests."""
import os
import tempfile
import unittest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from effect_authority import EffectAuthority
from signed_policy_floor import SignedPolicyFloor, sign_transition, verify_transition

def request(op="op1"):
    return {"operation_id": op, "kind": "fixture:write", "target": "fixture:protected", "value": 1}

class SignedFloorTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.authority = EffectAuthority(os.path.join(temp.name, "effects.sqlite"), lambda *args: True)
        self.key = Ed25519PrivateKey.generate()
        self.public = self.key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()
        self.floor = SignedPolicyFloor(self.authority, self.public, "tenant-a")

    def test_signed_revocation_blocks_stale_execution(self):
        self.assertTrue(self.floor.apply(sign_transition(self.key, "tenant-a", 8)))
        self.assertEqual(self.authority.commit(request(), 7), "DENIED")
        self.assertEqual(self.authority.commit(request(), 8), "APPLIED")

    def test_wrong_key_rejected(self):
        other = Ed25519PrivateKey.generate()
        self.assertFalse(self.floor.apply(sign_transition(other, "tenant-a", 9)))
        self.assertEqual(self.authority.commit(request(), 1), "APPLIED")

    def test_cross_tenant_replay_rejected(self):
        self.assertFalse(self.floor.apply(sign_transition(self.key, "tenant-b", 9)))
        self.assertEqual(self.authority.commit(request(), 1), "APPLIED")

    def test_signature_tampering_rejected(self):
        token = sign_transition(self.key, "tenant-a", 9)
        token["payload"]["generation"] = 10
        self.assertFalse(self.floor.apply(token))
        self.assertEqual(self.authority.commit(request(), 1), "APPLIED")

    def test_malformed_envelopes_fail_closed(self):
        for token in (None, {}, {"payload": {}, "signature": "zz"}, {"payload": [], "signature": ""}):
            self.assertFalse(self.floor.apply(token))

    def test_signed_floor_cannot_decrease(self):
        self.assertTrue(self.floor.apply(sign_transition(self.key, "tenant-a", 9)))
        self.assertTrue(self.floor.apply(sign_transition(self.key, "tenant-a", 2)))
        self.assertEqual(self.authority.commit(request(), 8), "DENIED")
        self.assertEqual(self.authority.commit(request(), 9), "APPLIED")

    def test_boolean_generation_rejected(self):
        with self.assertRaises(ValueError):
            sign_transition(self.key, "tenant-a", True)
        token = sign_transition(self.key, "tenant-a", 2)
        token["payload"]["generation"] = True
        self.assertIsNone(verify_transition(token, self.public, "tenant-a"))

if __name__ == "__main__":
    unittest.main()
