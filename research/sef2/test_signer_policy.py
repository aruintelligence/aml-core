import tempfile
import unittest
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from signer_policy import SignerPolicy

class SignerPolicyTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.key=Ed25519PrivateKey.generate()
        self.signer=SignerPolicy(Path(self.tmp.name)/"signer.sqlite",self.key,"issuer","broker")
        self.request={"operation_id":"op-1","action":"payment:simulate",
                      "target":"fixture:merchant-a","amount_cents":100}
    def test_authorized_scoped_action(self):
        token=self.signer.authorize(self.request,"a"*32)
        self.assertEqual(token["payload"]["audience"],"broker")
        self.assertEqual(token["payload"]["operation_id"],"op-1")
    def test_action_outside_allowlist_denied(self):
        bad=dict(self.request,action="payment:transfer")
        with self.assertRaises(PermissionError):self.signer.authorize(bad,"b"*32)
    def test_target_substitution_denied(self):
        bad=dict(self.request,target="fixture:attacker")
        with self.assertRaises(PermissionError):self.signer.authorize(bad,"c"*32)
    def test_amount_limit_and_bool_rejected(self):
        for amount in (0,501,True):
            with self.subTest(amount=amount):
                with self.assertRaises(PermissionError):
                    self.signer.authorize(dict(self.request,amount_cents=amount),str(amount)*32)
    def test_challenge_replay_denied(self):
        self.signer.authorize(self.request,"d"*32)
        with self.assertRaises(PermissionError):self.signer.authorize(self.request,"d"*32)
    def test_operation_replay_with_new_challenge_denied(self):
        self.signer.authorize(self.request,"e"*32)
        with self.assertRaises(PermissionError):self.signer.authorize(self.request,"f"*32)
    def test_malformed_challenge_denied(self):
        with self.assertRaises(PermissionError):self.signer.authorize(self.request,"short")
