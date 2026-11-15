import copy,unittest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from authenticated_execution_challenge import make_execution_challenge,verify_execution_challenge
from session_capability import issue_session_capability

class AuthenticatedExecutionChallengeTests(unittest.TestCase):
 def setUp(self):
  self.broker=Ed25519PrivateKey.generate(); self.other=Ed25519PrivateKey.generate()
  self.authority=Ed25519PrivateKey.generate(); self.holder=Ed25519PrivateKey.generate()
  self.request={"operation_id":"auth-challenge-op","action":"payment:simulate","target":"fixture:merchant-a","amount_cents":100}
  self.cap=issue_session_capability(self.authority,"issuer","broker-a",self.request,4,self.holder.public_key().public_bytes_raw().hex())
  self.env=make_execution_challenge(self.broker,"broker-instance-1","broker-a",self.request,self.cap,4,"c"*64)
  self.pub=self.broker.public_key().public_bytes_raw().hex()
 def test_exact_authenticated_challenge_accepts(self):
  self.assertTrue(verify_execution_challenge(self.env,self.pub,"broker-instance-1","broker-a",self.request,self.cap,4))
 def test_forged_broker_key_rejected(self):
  self.assertFalse(verify_execution_challenge(self.env,self.other.public_key().public_bytes_raw().hex(),"broker-instance-1","broker-a",self.request,self.cap,4))
 def test_broker_identity_substitution_rejected(self):
  self.assertFalse(verify_execution_challenge(self.env,self.pub,"broker-instance-2","broker-a",self.request,self.cap,4))
 def test_request_substitution_rejected(self):
  self.assertFalse(verify_execution_challenge(self.env,self.pub,"broker-instance-1","broker-a",dict(self.request,amount_cents=101),self.cap,4))
 def test_capability_substitution_rejected(self):
  cap2=issue_session_capability(self.authority,"issuer","broker-a",self.request,4,self.holder.public_key().public_bytes_raw().hex())
  self.assertFalse(verify_execution_challenge(self.env,self.pub,"broker-instance-1","broker-a",self.request,cap2,4))
 def test_epoch_substitution_rejected(self):
  self.assertFalse(verify_execution_challenge(self.env,self.pub,"broker-instance-1","broker-a",self.request,self.cap,5))
 def test_signature_tamper_rejected(self):
  changed=copy.deepcopy(self.env); changed["signature"]="00"*64
  self.assertFalse(verify_execution_challenge(changed,self.pub,"broker-instance-1","broker-a",self.request,self.cap,4))
 def test_challenge_tamper_rejected(self):
  changed=copy.deepcopy(self.env); changed["payload"]["challenge"]="d"*64
  self.assertFalse(verify_execution_challenge(changed,self.pub,"broker-instance-1","broker-a",self.request,self.cap,4))
