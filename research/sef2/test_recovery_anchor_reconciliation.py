import pathlib,tempfile,unittest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from threshold_recovery import RecoveryAuthoritySigner,MemoryRecoveryHeadAnchor
from recovery_anchor_reconciliation import reconcile_recovery_authority_anchor

class RecoveryAnchorReconciliationTests(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
  self.path=str(pathlib.Path(self.temp.name)/"authority.sqlite")
  self.key=Ed25519PrivateKey.generate()
  self.policy={"schema":"AML-SEF2-RECOVERY-QUORUM-POLICY-V1","policy_id":"council",
   "threshold":1,"max_faults":0,
   "authorities":{"authority-0":self.key.public_key().public_bytes_raw().hex()}}
  self.anchor=MemoryRecoveryHeadAnchor()
  class FailOnce:
   def __init__(self,inner): self.inner=inner; self.fail=True
   def read_head(self): return self.inner.read_head()
   def compare_and_set(self,old,new):
    if self.fail:
     self.fail=False
     return False
    return self.inner.compare_and_set(old,new)
  self.failing_anchor=FailOnce(self.anchor)
  self.payload={"witness_id":"north","generation":1,"previous_state_sha256":"a"*64}
 def test_interrupted_local_commit_can_be_reconciled_from_external_predecessor(self):
  signer=RecoveryAuthoritySigner("authority-0",self.key,self.path,head_anchor=self.failing_anchor)
  with self.assertRaisesRegex(RuntimeError,"committed locally"):
   signer.approve(self.payload,self.policy)
  result=reconcile_recovery_authority_anchor("authority-0",self.key,self.path,
      self.failing_anchor,"0"*64)
  self.assertEqual(result,"RECONCILED")
  reopened=RecoveryAuthoritySigner("authority-0",self.key,self.path,head_anchor=self.anchor)
  self.assertEqual(reopened.approve(self.payload,self.policy),
      reopened.export_approval_ledger()["events"][0]["signature"])
 def test_wrong_predecessor_never_advances_anchor(self):
  signer=RecoveryAuthoritySigner("authority-0",self.key,self.path)
  signer.approve(self.payload,self.policy)
  self.assertEqual(reconcile_recovery_authority_anchor("authority-0",self.key,self.path,
      self.anchor,"f"*64),"EXPECTED_PREDECESSOR_MISMATCH")
  self.assertEqual(self.anchor.read_head(),"0"*64)
 def test_wrong_authority_identity_rejected(self):
  signer=RecoveryAuthoritySigner("authority-0",self.key,self.path)
  signer.approve(self.payload,self.policy)
  self.assertEqual(reconcile_recovery_authority_anchor("other",self.key,self.path,
      self.anchor,"0"*64),"AUTHORITY_IDENTITY_MISMATCH")
 def test_no_pending_event_is_idempotently_current(self):
  signer=RecoveryAuthoritySigner("authority-0",self.key,self.path,head_anchor=self.anchor)
  self.assertEqual(reconcile_recovery_authority_anchor("authority-0",self.key,self.path,
      self.anchor,"0"*64),"ALREADY_CURRENT")

 def test_multiple_unanchored_events_cannot_be_reconciled_as_one(self):
  signer=RecoveryAuthoritySigner("authority-0",self.key,self.path)
  signer.approve(self.payload,self.policy)
  signer.approve({**self.payload,"generation":2,"previous_state_sha256":"c"*64},self.policy)
  self.assertEqual(reconcile_recovery_authority_anchor("authority-0",self.key,self.path,
      self.anchor,"0"*64),"EXPECTED_PREDECESSOR_MISMATCH")
  self.assertEqual(self.anchor.read_head(),"0"*64)
 def test_tampered_local_ledger_cannot_be_reconciled(self):
  import sqlite3
  signer=RecoveryAuthoritySigner("authority-0",self.key,self.path)
  signer.approve(self.payload,self.policy)
  with sqlite3.connect(self.path) as con:
   con.execute("UPDATE recovery_approval_events SET payload_sha256=? WHERE sequence=1",("f"*64,))
  self.assertEqual(reconcile_recovery_authority_anchor("authority-0",self.key,self.path,
      self.anchor,"0"*64),"INVALID_LOCAL_LEDGER")
  self.assertEqual(self.anchor.read_head(),"0"*64)
