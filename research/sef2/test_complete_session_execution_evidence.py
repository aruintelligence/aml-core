import copy,unittest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from authenticated_execution_challenge import make_execution_challenge
from execution_consumption_witness import make_consumption_receipt
from session_capability import issue_session_capability,make_holder_proof
from evaluation_kit.verify_session_authorization import SCHEMA as AUTH_SCHEMA
from evaluation_kit.verify_complete_session_execution import verify_complete,SCHEMA

class CompleteSessionExecutionEvidenceTests(unittest.TestCase):
 def setUp(self):
  self.authority=Ed25519PrivateKey.generate(); self.broker=Ed25519PrivateKey.generate()
  self.holder=Ed25519PrivateKey.generate(); self.witness=Ed25519PrivateKey.generate()
  self.request={"operation_id":"complete-session-op","action":"payment:simulate","target":"fixture:merchant-a","amount_cents":100}
  self.cap=issue_session_capability(self.authority,"authority","broker-a",self.request,6,
   self.holder.public_key().public_bytes_raw().hex())
  self.challenge=make_execution_challenge(self.broker,"broker-instance-complete","broker-a",
   self.request,self.cap,6,"c"*64)
  self.proof=make_holder_proof(self.holder,self.cap,self.request,"c"*64)
  auth={"schema":AUTH_SCHEMA,"request":self.request,"capability":self.cap,
   "broker_challenge":self.challenge,"holder_proof":self.proof}
  receipt=make_consumption_receipt(self.witness,"execution-witness-complete",
   self.request,self.cap,"c"*64)
  self.bundle={"schema":SCHEMA,"authorization":auth,"consumption_receipt":receipt}
  self.args=(self.authority.public_key().public_bytes_raw().hex(),
   self.broker.public_key().public_bytes_raw().hex(),
   self.witness.public_key().public_bytes_raw().hex(),
   "authority","broker-a","broker-instance-complete","execution-witness-complete",6)
 def check(self,b=None): return verify_complete(self.bundle if b is None else b,*self.args)
 def test_complete_authorization_and_consumption_chain_accepts(self): self.assertTrue(self.check())
 def test_valid_consumption_receipt_with_forged_authority_capability_rejected(self):
  b=copy.deepcopy(self.bundle); b["authorization"]["capability"]["signature"]="00"*64
  self.assertFalse(self.check(b))
 def test_valid_authorization_with_wrong_consumption_witness_rejected(self):
  args=list(self.args); args[2]=Ed25519PrivateKey.generate().public_key().public_bytes_raw().hex()
  self.assertFalse(verify_complete(self.bundle,*args))
 def test_holder_proof_tamper_rejected(self):
  b=copy.deepcopy(self.bundle); b["authorization"]["holder_proof"]["signature"]="00"*64
  self.assertFalse(self.check(b))
 def test_broker_challenge_tamper_rejected(self):
  b=copy.deepcopy(self.bundle); b["authorization"]["broker_challenge"]["signature"]="00"*64
  self.assertFalse(self.check(b))
 def test_consumption_receipt_from_other_challenge_rejected(self):
  b=copy.deepcopy(self.bundle)
  b["consumption_receipt"]=make_consumption_receipt(self.witness,"execution-witness-complete",
   self.request,self.cap,"d"*64)
  self.assertFalse(self.check(b))
 def test_request_substitution_rejected_across_both_layers(self):
  b=copy.deepcopy(self.bundle); b["authorization"]["request"]["amount_cents"]=101
  self.assertFalse(self.check(b))
 def test_extra_execution_claim_is_rejected(self):
  b=copy.deepcopy(self.bundle); b["effect_claim"]="paid"
  self.assertFalse(self.check(b))
