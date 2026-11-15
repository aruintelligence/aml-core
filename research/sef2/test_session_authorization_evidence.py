import copy,json,pathlib,tempfile,unittest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from authenticated_execution_challenge import make_execution_challenge
from session_capability import issue_session_capability,make_holder_proof
from evaluation_kit.verify_session_authorization import verify_session_authorization,decision_digest,SCHEMA

class SessionAuthorizationEvidenceTests(unittest.TestCase):
 def setUp(self):
  self.authority=Ed25519PrivateKey.generate(); self.broker=Ed25519PrivateKey.generate(); self.holder=Ed25519PrivateKey.generate()
  self.request={"operation_id":"audit-session","action":"payment:simulate","target":"fixture:merchant-a","amount_cents":100}
  self.cap=issue_session_capability(self.authority,"authority","broker-a",self.request,5,
   self.holder.public_key().public_bytes_raw().hex())
  self.challenge=make_execution_challenge(self.broker,"broker-instance-a","broker-a",
   self.request,self.cap,5,"c"*64)
  self.proof=make_holder_proof(self.holder,self.cap,self.request,"c"*64)
  self.bundle={"schema":SCHEMA,"request":self.request,"capability":self.cap,
   "broker_challenge":self.challenge,"holder_proof":self.proof}
  self.args=(self.authority.public_key().public_bytes_raw().hex(),
   self.broker.public_key().public_bytes_raw().hex(),"authority","broker-a","broker-instance-a",5)
 def check(self,bundle=None):
  return verify_session_authorization(self.bundle if bundle is None else bundle,*self.args)
 def test_complete_public_chain_verifies(self):
  self.assertTrue(self.check())
  self.assertEqual(len(decision_digest(self.bundle)),64)
 def test_wrong_authority_pin_rejected(self):
  args=(Ed25519PrivateKey.generate().public_key().public_bytes_raw().hex(),)+self.args[1:]
  self.assertFalse(verify_session_authorization(self.bundle,*args))
 def test_wrong_broker_pin_rejected(self):
  args=(self.args[0],Ed25519PrivateKey.generate().public_key().public_bytes_raw().hex())+self.args[2:]
  self.assertFalse(verify_session_authorization(self.bundle,*args))
 def test_request_tamper_rejected(self):
  b=copy.deepcopy(self.bundle); b["request"]["amount_cents"]=101
  self.assertFalse(self.check(b))
 def test_capability_signature_tamper_rejected(self):
  b=copy.deepcopy(self.bundle); b["capability"]["signature"]="00"*64
  self.assertFalse(self.check(b))
 def test_broker_challenge_tamper_rejected(self):
  b=copy.deepcopy(self.bundle); b["broker_challenge"]["payload"]["challenge"]="d"*64
  self.assertFalse(self.check(b))
 def test_holder_proof_tamper_rejected(self):
  b=copy.deepcopy(self.bundle); b["holder_proof"]["signature"]="00"*64
  self.assertFalse(self.check(b))
 def test_stale_policy_epoch_rejected(self):
  self.assertFalse(verify_session_authorization(self.bundle,*self.args[:-1],6))
 def test_wrong_broker_identity_rejected(self):
  self.assertFalse(verify_session_authorization(self.bundle,*self.args[:4],"other-broker",5))
 def test_extra_fields_rejected(self):
  b=copy.deepcopy(self.bundle); b["claimed_execution"]="APPLIED"
  self.assertFalse(self.check(b))
