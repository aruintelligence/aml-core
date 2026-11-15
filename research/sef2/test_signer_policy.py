import tempfile
import unittest
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from signer_policy import SignerPolicy
from broker_intent import create_intent

class SignerPolicyTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.key=Ed25519PrivateKey.generate()
        self.broker_key=Ed25519PrivateKey.generate()
        self.signer=SignerPolicy(Path(self.tmp.name)/"signer.sqlite",self.key,"issuer","broker",
            "broker-1",self.broker_key.public_key().public_bytes_raw().hex())
        self.request={"operation_id":"op-1","action":"payment:simulate",
                      "target":"fixture:merchant-a","amount_cents":100}
        self.counter=0

    def intent(self,request=None,challenge=None,key=None,broker_id="broker-1",audience="broker"):
        self.counter+=1
        return create_intent(key or self.broker_key,broker_id,audience,request or self.request,
                             challenge or ("n"*31+str(self.counter)))

    def test_authorized_scoped_action(self):
        token=self.signer.authorize(self.request,self.intent())
        self.assertEqual(token["payload"]["audience"],"broker")
        self.assertEqual(token["payload"]["operation_id"],"op-1")

    def test_agent_cannot_supply_unsigned_challenge(self):
        with self.assertRaises(PermissionError):self.signer.authorize(self.request,{"challenge":"x"*32})

    def test_wrong_broker_key_denied(self):
        with self.assertRaises(PermissionError):
            self.signer.authorize(self.request,self.intent(key=Ed25519PrivateKey.generate()))

    def test_wrong_broker_identity_denied(self):
        with self.assertRaises(PermissionError):
            self.signer.authorize(self.request,self.intent(broker_id="attacker"))

    def test_wrong_audience_denied(self):
        with self.assertRaises(PermissionError):
            self.signer.authorize(self.request,self.intent(audience="other-broker"))

    def test_request_substitution_denied(self):
        intent=self.intent()
        with self.assertRaises(PermissionError):
            self.signer.authorize(dict(self.request,amount_cents=101),intent)

    def test_action_outside_allowlist_denied(self):
        signed=self.intent()
        bad=dict(self.request,action="payment:transfer")
        with self.assertRaises(PermissionError):self.signer.authorize(bad,signed)

    def test_target_substitution_denied(self):
        signed=self.intent()
        bad=dict(self.request,target="fixture:attacker")
        with self.assertRaises(PermissionError):self.signer.authorize(bad,signed)

    def test_amount_limit_and_bool_rejected(self):
        signed=self.intent()
        for amount in (0,501,True):
            with self.subTest(amount=amount):
                bad=dict(self.request,amount_cents=amount)
                with self.assertRaises(PermissionError):self.signer.authorize(bad,signed)

    def test_signed_challenge_replay_denied(self):
        intent=self.intent(challenge="d"*32)
        self.signer.authorize(self.request,intent)
        with self.assertRaises(PermissionError):self.signer.authorize(self.request,intent)

    def test_operation_replay_with_new_signed_challenge_denied(self):
        self.signer.authorize(self.request,self.intent(challenge="e"*32))
        with self.assertRaises(PermissionError):
            self.signer.authorize(self.request,self.intent(challenge="f"*32))

    def test_malformed_challenge_denied(self):
        with self.assertRaises(ValueError):
            self.intent(challenge="short")
