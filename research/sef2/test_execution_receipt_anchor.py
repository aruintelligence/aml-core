import copy,pathlib,tempfile,unittest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from execution_consumption_witness import make_consumption_receipt
from execution_receipt_anchor import ExecutionReceiptAnchor
from session_capability import issue_session_capability

class ExecutionReceiptAnchorTests(unittest.TestCase):
 def setUp(self):
  t=tempfile.TemporaryDirectory(); self.addCleanup(t.cleanup); self.root=pathlib.Path(t.name)
  self.key=Ed25519PrivateKey.generate(); self.authority=Ed25519PrivateKey.generate(); self.holder=Ed25519PrivateKey.generate()
  self.request={"operation_id":"anchor-op","action":"payment:simulate","target":"fixture:merchant-a","amount_cents":100}
  self.cap=issue_session_capability(self.authority,"authority","broker-a",self.request,0,
   self.holder.public_key().public_bytes_raw().hex())
  self.anchor=ExecutionReceiptAnchor(self.root/"anchor.sqlite","execution-witness-1",
   self.key.public_key().public_bytes_raw().hex())
  self.first=make_consumption_receipt(self.key,"execution-witness-1",self.request,self.cap,"a"*64)
 def test_first_signed_head_is_anchored(self):
  self.assertEqual(self.anchor.accept(self.first),"ANCHORED")
  self.assertEqual(self.anchor.state()["sequence"],1)
 def test_same_receipt_anchor_is_idempotent(self):
  self.anchor.accept(self.first); self.assertEqual(self.anchor.accept(self.first),"ANCHORED")
 def test_second_receipt_must_link_to_first_head(self):
  self.anchor.accept(self.first)
  req2=dict(self.request,operation_id="anchor-op-2")
  cap2=issue_session_capability(self.authority,"authority","broker-a",req2,0,
   self.holder.public_key().public_bytes_raw().hex())
  second=make_consumption_receipt(self.key,"execution-witness-1",req2,cap2,"b"*64,
   2,self.first["payload"]["entry_hash"])
  self.assertEqual(self.anchor.accept(second),"ANCHORED")
  self.assertEqual(self.anchor.state()["sequence"],2)
 def test_rolled_back_sequence_rejected(self):
  self.anchor.accept(self.first)
  req2=dict(self.request,operation_id="fork")
  cap2=issue_session_capability(self.authority,"authority","broker-a",req2,0,
   self.holder.public_key().public_bytes_raw().hex())
  stale=make_consumption_receipt(self.key,"execution-witness-1",req2,cap2,"b"*64)
  with self.assertRaises(PermissionError): self.anchor.accept(stale)
 def test_wrong_witness_key_rejected(self):
  bad=make_consumption_receipt(Ed25519PrivateKey.generate(),"execution-witness-1",
   self.request,self.cap,"a"*64)
  with self.assertRaises(PermissionError): self.anchor.accept(bad)
 def test_entry_hash_tamper_rejected(self):
  bad=copy.deepcopy(self.first); bad["payload"]["entry_hash"]="f"*64
  with self.assertRaises(PermissionError): self.anchor.accept(bad)
 def test_witness_key_substitution_on_restart_rejected(self):
  with self.assertRaises(ValueError):
   ExecutionReceiptAnchor(self.root/"anchor.sqlite","execution-witness-1",
    Ed25519PrivateKey.generate().public_key().public_bytes_raw().hex())
