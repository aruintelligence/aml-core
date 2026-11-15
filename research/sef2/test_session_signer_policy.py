import pathlib,tempfile,unittest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from broker_intent import create_intent
from session_signer_policy import SessionSignerPolicy
from session_capability import verify_session_capability,make_holder_proof,verify_holder_proof
from signer_policy import SignerPolicy

class SessionSignerPolicyTests(unittest.TestCase):
 def setUp(self):
  tmp=tempfile.TemporaryDirectory(); self.addCleanup(tmp.cleanup)
  self.db=pathlib.Path(tmp.name)/"signer.sqlite"
  self.authority=Ed25519PrivateKey.generate()
  self.broker=Ed25519PrivateKey.generate()
  self.holder=Ed25519PrivateKey.generate()
  self.other=Ed25519PrivateKey.generate()
  self.request={"operation_id":"session-sign-op","action":"payment:simulate",
   "target":"fixture:merchant-a","amount_cents":100}
  self.policy=SessionSignerPolicy(self.db,self.authority,"authority","broker-a","broker-1",
   self.broker.public_key().public_bytes_raw().hex(),
   self.holder.public_key().public_bytes_raw().hex(),4)
 def intent(self,request=None,challenge="c"*48):
  request=request or self.request
  return create_intent(self.broker,"broker-1","broker-a",request,challenge)
 def test_signer_issues_capability_only_for_enrolled_holder(self):
  cap=self.policy.authorize(self.request,self.intent())
  self.assertTrue(verify_session_capability(cap,self.authority.public_key().public_bytes_raw().hex(),
   "authority","broker-a",self.request,4))
  self.assertEqual(cap["payload"]["holder_public_key_hex"],self.holder.public_key().public_bytes_raw().hex())
  proof=make_holder_proof(self.holder,cap,self.request,"d"*64)
  self.assertTrue(verify_holder_proof(proof,cap,self.request,"d"*64))
 def test_different_holder_cannot_use_issued_capability(self):
  cap=self.policy.authorize(self.request,self.intent())
  with self.assertRaises(ValueError):
   make_holder_proof(self.other,cap,self.request,"d"*64)
 def test_restart_with_different_holder_enrollment_rejected(self):
  self.policy.authorize(self.request,self.intent())
  with self.assertRaises(ValueError):
   SessionSignerPolicy(self.db,self.authority,"authority","broker-a","broker-1",
    self.broker.public_key().public_bytes_raw().hex(),
    self.other.public_key().public_bytes_raw().hex(),4)
 def test_broker_intent_substitution_rejected(self):
  with self.assertRaises(PermissionError):
   self.policy.authorize(dict(self.request,amount_cents=101),self.intent())
 def test_wrong_broker_key_rejected(self):
  fake=create_intent(self.other,"broker-1","broker-a",self.request,"e"*48)
  with self.assertRaises(PermissionError): self.policy.authorize(self.request,fake)
 def test_session_authorization_replay_rejected(self):
  self.policy.authorize(self.request,self.intent())
  with self.assertRaises(PermissionError):
   self.policy.authorize(self.request,self.intent(challenge="e"*48))
 def test_legacy_and_session_capabilities_share_operation_consumption(self):
  legacy=SignerPolicy(self.db,self.authority,"authority","broker-a","broker-1",
   self.broker.public_key().public_bytes_raw().hex(),4)
  legacy.authorize(self.request,self.intent(challenge="f"*48))
  with self.assertRaises(PermissionError):
   self.policy.authorize(self.request,self.intent(challenge="g"*48))
 def test_session_then_legacy_cannot_double_authorize(self):
  self.policy.authorize(self.request,self.intent(challenge="h"*48))
  legacy=SignerPolicy(self.db,self.authority,"authority","broker-a","broker-1",
   self.broker.public_key().public_bytes_raw().hex(),4)
  with self.assertRaises(PermissionError):
   legacy.authorize(self.request,self.intent(challenge="i"*48))
