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
      self.anchor,"f"*64),"EXTERNAL_PREDECESSOR_MISMATCH")
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

 def test_cas_success_with_lost_response_is_idempotently_reconciled(self):
  class ApplyThenLoseResponse:
   def __init__(self,inner): self.inner=inner
   def read_head(self): return self.inner.read_head()
   def compare_and_set(self,old,new):
    self.inner.compare_and_set(old,new)
    return False
  lost=ApplyThenLoseResponse(self.anchor)
  signer=RecoveryAuthoritySigner("authority-0",self.key,self.path,head_anchor=lost)
  with self.assertRaisesRegex(RuntimeError,"committed locally"):
   signer.approve(self.payload,self.policy)
  self.assertNotEqual(self.anchor.read_head(),"0"*64)
  result=reconcile_recovery_authority_anchor("authority-0",self.key,self.path,lost,"0"*64)
  self.assertEqual(result,"ALREADY_CURRENT")
 def test_external_anchor_divergence_is_not_reported_as_current(self):
  signer=RecoveryAuthoritySigner("authority-0",self.key,self.path)
  signer.approve(self.payload,self.policy)
  self.anchor.compare_and_set("0"*64,"f"*64)
  self.assertEqual(reconcile_recovery_authority_anchor("authority-0",self.key,self.path,
      self.anchor,"0"*64),"EXTERNAL_PREDECESSOR_MISMATCH")
 def test_already_anchored_local_head_is_idempotent(self):
  signer=RecoveryAuthoritySigner("authority-0",self.key,self.path,head_anchor=self.anchor)
  signer.approve(self.payload,self.policy)
  head=signer.export_approval_ledger()["head_sha256"]
  self.assertEqual(self.anchor.read_head(),head)
  self.assertEqual(reconcile_recovery_authority_anchor("authority-0",self.key,self.path,
      self.anchor,"0"*64),"ALREADY_CURRENT")

 def test_two_two_partial_quorum_cas_is_repaired_from_retained_predecessor(self):
  from threshold_recovery import MemoryRecoveryHeadAnchor,QuorumRecoveryHeadAnchor
  signer=RecoveryAuthoritySigner("authority-0",self.key,self.path)
  signer.approve(self.payload,self.policy)
  local_head=signer.export_approval_ledger()["head_sha256"]
  anchors=[MemoryRecoveryHeadAnchor(f"anchor-{i}") for i in range(4)]
  for anchor in anchors[:2]:
   self.assertTrue(anchor.compare_and_set("0"*64,local_head))
  quorum=QuorumRecoveryHeadAnchor(anchors,3,1)
  with self.assertRaisesRegex(RuntimeError,"no unique quorum"):
   quorum.read_head()
  result=reconcile_recovery_authority_anchor("authority-0",self.key,self.path,quorum,"0"*64)
  self.assertEqual(result,"RECONCILED")
  self.assertEqual(quorum.read_head(),local_head)
  self.assertTrue(all(anchor.read_head()==local_head for anchor in anchors))
 def test_conflicting_two_two_anchor_split_fails_closed_without_mutation(self):
  from threshold_recovery import MemoryRecoveryHeadAnchor,QuorumRecoveryHeadAnchor
  signer=RecoveryAuthoritySigner("authority-0",self.key,self.path)
  signer.approve(self.payload,self.policy)
  local_head=signer.export_approval_ledger()["head_sha256"]
  anchors=[MemoryRecoveryHeadAnchor() for _ in range(4)]
  for anchor in anchors[:2]: anchor.compare_and_set("0"*64,local_head)
  for anchor in anchors[2:]: anchor.compare_and_set("0"*64,"f"*64)
  quorum=QuorumRecoveryHeadAnchor(anchors,3,1)
  self.assertEqual(reconcile_recovery_authority_anchor("authority-0",self.key,self.path,
      quorum,"0"*64),"ANCHOR_RECONCILIATION_FAILED")
  self.assertEqual([anchor.read_head() for anchor in anchors],[local_head,local_head,"f"*64,"f"*64])
