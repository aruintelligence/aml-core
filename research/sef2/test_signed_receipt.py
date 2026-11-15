import copy
import unittest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from signed_receipt import issue, verify, reconcile, key_id

class SignedReceiptTests(unittest.TestCase):
    def setUp(self):
        self.a = Ed25519PrivateKey.generate()
        self.p = Ed25519PrivateKey.generate()
        self.keys = {"authority": {key_id(self.a.public_key()): self.a.public_key()},
            "provider": {key_id(self.p.public_key()): self.p.public_key()}}
        self.auth = issue(self.a, "authority", "op1", "a"*64, "CONSUMED", "b"*64)
        self.provider = issue(self.p, "provider", "op1", "a"*64, "PROVIDER_REPORTED", "c"*64)

    def test_public_keys_verify_without_private_keys(self):
        self.assertTrue(verify(self.auth, "authority", self.keys))
        self.assertEqual(reconcile(self.auth, self.provider, self.keys), "SIGNED_CLAIMS_ONLY")

    def test_tamper_rejected(self):
        changed = copy.deepcopy(self.provider)
        changed["payload"]["state"] = "CONSUMED"
        self.assertFalse(verify(changed, "provider", self.keys))

    def test_role_confusion_rejected(self):
        self.assertFalse(verify(self.auth, "provider", self.keys))

    def test_unknown_key_rejected(self):
        self.assertFalse(verify(self.auth, "authority", {"authority": {}, "provider": {}}))

    def test_key_rotation_accepts_trusted_old_and_new(self):
        rotated = Ed25519PrivateKey.generate()
        new_receipt = issue(rotated, "authority", "op1", "a"*64, "CONSUMED", "b"*64)
        self.assertFalse(verify(new_receipt, "authority", self.keys))
        self.keys["authority"][key_id(rotated.public_key())] = rotated.public_key()
        self.assertTrue(verify(new_receipt, "authority", self.keys))
        self.assertTrue(verify(self.auth, "authority", self.keys))

    def test_cross_request_binding(self):
        other = issue(self.p, "provider", "op1", "d"*64, "PROVIDER_REPORTED", "c"*64)
        self.assertEqual(reconcile(self.auth, other, self.keys), "EVIDENCE_CONFLICT")

    def test_valid_signature_does_not_imply_execution(self):
        false_claim = issue(self.p, "provider", "op1", "a"*64, "PROVIDER_REPORTED", "c"*64)
        self.assertTrue(verify(false_claim, "provider", self.keys))
        self.assertEqual(reconcile(self.auth, false_claim, self.keys), "SIGNED_CLAIMS_ONLY")

    def test_malformed_signature_rejected(self):
        changed = copy.deepcopy(self.auth)
        changed["signature"] = "not hex"
        self.assertFalse(verify(changed, "authority", self.keys))
