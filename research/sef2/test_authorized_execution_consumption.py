import copy,pathlib,tempfile,unittest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from session_capability import issue_session_capability
from authorized_execution_consumption import (AuthorizedExecutionConsumptionWitness,
 make_authorized_consumption_receipt,verify_authorized_consumption_receipt)

class AuthorizedExecutionConsumptionTests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
  self.key=Ed25519PrivateKey.generate(); self.authority=Ed25519PrivateKey.generate()
  self.holder=Ed25519PrivateKey.generate()
  self.request={"operation_id":"full-auth-op","action":"payment:simulate",
   "target":"fixture:merchant-a","amount_cents":100}
  self.cap=issue_session_capability(self.authority,"authority","broker-a",self.request,0,
    self.holder.public_key().public_bytes_raw().hex())
  self.challenge="c"*64
  self.holder_proof={"payload":{"proof":"holder-a"},"signature":"11"*64}
  self.evaluator={"payload":{"decision":"allow","registry":"r1"},"signature":"22"*64}
  self.witness=AuthorizedExecutionConsumptionWitness(pathlib.Path(self.tmp.name)/"witness.sqlite")
 def test_receipt_binds_exact_full_authorization_tuple(self):
  entry=self.witness.consume_record(self.request,self.cap,self.challenge,self.holder_proof,self.evaluator)
  receipt=make_authorized_consumption_receipt(self.key,"witness-v3",entry)
  self.assertTrue(verify_authorized_consumption_receipt(receipt,
    self.key.public_key().public_bytes_raw().hex(),"witness-v3",self.request,self.cap,
    self.challenge,self.holder_proof,self.evaluator))
 def test_different_holder_proof_cannot_be_spliced_into_receipt(self):
  entry=self.witness.consume_record(self.request,self.cap,self.challenge,self.holder_proof,self.evaluator)
  receipt=make_authorized_consumption_receipt(self.key,"witness-v3",entry)
  other=copy.deepcopy(self.holder_proof); other["payload"]["proof"]="holder-b"
  self.assertFalse(verify_authorized_consumption_receipt(receipt,
    self.key.public_key().public_bytes_raw().hex(),"witness-v3",self.request,self.cap,
    self.challenge,other,self.evaluator))
 def test_different_evaluator_authorization_cannot_be_spliced(self):
  entry=self.witness.consume_record(self.request,self.cap,self.challenge,self.holder_proof,self.evaluator)
  receipt=make_authorized_consumption_receipt(self.key,"witness-v3",entry)
  other=copy.deepcopy(self.evaluator); other["payload"]["registry"]="r2"
  self.assertFalse(verify_authorized_consumption_receipt(receipt,
    self.key.public_key().public_bytes_raw().hex(),"witness-v3",self.request,self.cap,
    self.challenge,self.holder_proof,other))
 def test_operation_replay_denied_even_with_different_full_authorization(self):
  self.witness.consume_record(self.request,self.cap,self.challenge,self.holder_proof,self.evaluator)
  other=copy.deepcopy(self.evaluator); other["payload"]["registry"]="r2"
  with self.assertRaises(PermissionError):
   self.witness.consume_record(self.request,self.cap,self.challenge,self.holder_proof,other)
 def test_monotonic_chain_links_full_authorization_entries(self):
  first=self.witness.consume_record(self.request,self.cap,self.challenge,self.holder_proof,self.evaluator)
  request2=dict(self.request,operation_id="full-auth-op-2")
  cap2=issue_session_capability(self.authority,"authority","broker-a",request2,0,
    self.holder.public_key().public_bytes_raw().hex())
  second=self.witness.consume_record(request2,cap2,"d"*64,self.holder_proof,self.evaluator)
  self.assertEqual(first["sequence"],1); self.assertEqual(second["sequence"],2)
  self.assertEqual(second["previous_hash"],first["entry_hash"])
