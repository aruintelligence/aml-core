import pathlib,tempfile,unittest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from execution_consumption_witness import ExecutionConsumptionWitness
from session_capability import issue_session_capability

class ExecutionConsumptionWitnessTests(unittest.TestCase):
 def setUp(self):
  t=tempfile.TemporaryDirectory(); self.addCleanup(t.cleanup); self.root=pathlib.Path(t.name)
  self.w=ExecutionConsumptionWitness(self.root/"execution.sqlite")
  self.authority=Ed25519PrivateKey.generate(); self.holder=Ed25519PrivateKey.generate()
  self.request={"operation_id":"consume-op","action":"payment:simulate","target":"fixture:merchant-a","amount_cents":100}
  self.cap=issue_session_capability(self.authority,"authority","broker-a",self.request,0,
   self.holder.public_key().public_bytes_raw().hex())
 def test_first_consumption_records_exact_scope(self):
  self.assertEqual(self.w.consume(self.request,self.cap,"c"*64),"CONSUMED")
  record=self.w.lookup("consume-op")
  self.assertEqual(record["operation_id"],"consume-op")
  self.assertEqual(len(record["request_sha256"]),64)
 def test_exact_replay_is_denied_not_idempotently_reexecuted(self):
  self.w.consume(self.request,self.cap,"c"*64)
  with self.assertRaises(PermissionError): self.w.consume(self.request,self.cap,"c"*64)
 def test_same_operation_different_challenge_still_denied(self):
  self.w.consume(self.request,self.cap,"c"*64)
  with self.assertRaises(PermissionError): self.w.consume(self.request,self.cap,"d"*64)
 def test_same_operation_different_request_still_denied(self):
  self.w.consume(self.request,self.cap,"c"*64)
  changed=dict(self.request,amount_cents=101)
  cap2=issue_session_capability(self.authority,"authority","broker-a",changed,0,
   self.holder.public_key().public_bytes_raw().hex())
  with self.assertRaises(PermissionError): self.w.consume(changed,cap2,"e"*64)
 def test_restart_retains_consumption(self):
  self.w.consume(self.request,self.cap,"c"*64)
  restarted=ExecutionConsumptionWitness(self.root/"execution.sqlite")
  with self.assertRaises(PermissionError): restarted.consume(self.request,self.cap,"c"*64)
