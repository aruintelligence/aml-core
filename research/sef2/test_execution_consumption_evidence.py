import copy,unittest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from execution_consumption_witness import make_consumption_receipt
from session_capability import issue_session_capability
from evaluation_kit.verify_execution_consumption import verify_bundle

class ExecutionConsumptionEvidenceTests(unittest.TestCase):
 def setUp(self):
  self.witness=Ed25519PrivateKey.generate(); self.authority=Ed25519PrivateKey.generate()
  self.holder=Ed25519PrivateKey.generate()
  self.request={"operation_id":"audit-consume","action":"payment:simulate","target":"fixture:merchant-a","amount_cents":100}
  self.cap=issue_session_capability(self.authority,"authority","broker-a",self.request,0,
   self.holder.public_key().public_bytes_raw().hex())
  self.challenge="c"*64
  self.receipt=make_consumption_receipt(self.witness,"execution-witness-1",
   self.request,self.cap,self.challenge)
  self.bundle={"schema":"AML-SEF2-EXECUTION-CONSUMPTION-EVIDENCE-V1",
   "request":self.request,"capability":self.cap,"challenge":self.challenge,"receipt":self.receipt}
  self.pub=self.witness.public_key().public_bytes_raw().hex()
 def check(self,b=None,pub=None,witness_id="execution-witness-1"):
  return verify_bundle(self.bundle if b is None else b,pub or self.pub,witness_id)
 def test_exact_public_evidence_verifies(self):
  self.assertEqual(self.receipt["payload"]["schema"],"AML-SEF2-EXECUTION-CONSUMPTION-RECEIPT-V2")
  self.assertTrue(self.check())
 def test_wrong_witness_key_rejected(self):
  self.assertFalse(self.check(pub=Ed25519PrivateKey.generate().public_key().public_bytes_raw().hex()))
 def test_wrong_witness_identity_rejected(self): self.assertFalse(self.check(witness_id="other"))
 def test_request_substitution_rejected(self):
  b=copy.deepcopy(self.bundle); b["request"]["amount_cents"]=101; self.assertFalse(self.check(b))
 def test_capability_substitution_rejected(self):
  b=copy.deepcopy(self.bundle); b["capability"]["signature"]="00"*64; self.assertFalse(self.check(b))
 def test_challenge_substitution_rejected(self):
  b=copy.deepcopy(self.bundle); b["challenge"]="d"*64; self.assertFalse(self.check(b))
 def test_receipt_signature_tamper_rejected(self):
  b=copy.deepcopy(self.bundle); b["receipt"]["signature"]="00"*64; self.assertFalse(self.check(b))
 def test_receipt_operation_tamper_rejected(self):
  b=copy.deepcopy(self.bundle); b["receipt"]["payload"]["operation_id"]="other"; self.assertFalse(self.check(b))
 def test_claimed_effect_field_is_rejected(self):
  b=copy.deepcopy(self.bundle); b["effect"]="APPLIED"; self.assertFalse(self.check(b))
