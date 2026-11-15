import pathlib,shutil,tempfile,unittest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from trust_enrollment import Enrollment,propose
from witness_key_recovery import make_transition
from witness_recovery_enrollment import WitnessRecoveryEnrollment
from anchored_witness_recovery import AnchoredWitnessRecovery
from threshold_recovery import MemoryRecoveryHeadAnchor

def pub(k): return k.public_key().public_bytes_raw().hex()
def cp(epoch=1,head="a"*64):
 return {"schema":"AML-SEF2-SIGNED-HISTORY-CHECKPOINT-V1","epoch":epoch,
  "head_hash":head,"count":epoch,"approver_key_id":"c"*64}

class AnchoredWitnessRecoveryTests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
  self.trust=str(pathlib.Path(self.tmp.name)/"trust.sqlite")
  self.recovery=str(pathlib.Path(self.tmp.name)/"recovery.sqlite")
  approver=Ed25519PrivateKey.generate(); self.root=Ed25519PrivateKey.generate()
  self.old=Ed25519PrivateKey.generate(); self.new=Ed25519PrivateKey.generate()
  keys={"authority":pub(Ed25519PrivateKey.generate()),
    "provider":pub(Ed25519PrivateKey.generate()),"witness":pub(self.old)}
  enrollment=Enrollment(self.trust,approver.public_key()); enrollment.accept(propose(approver,1,keys))
  self.inner=WitnessRecoveryEnrollment(self.trust,self.recovery,self.root.public_key(),"root")
  self.anchor=MemoryRecoveryHeadAnchor("witness-recovery-anchor")
  self.coordinator=AnchoredWitnessRecovery(self.inner,self.anchor)
  self.state=self.coordinator.initialize("north",cp())
  self.transition=make_transition(self.root,self.new,"north",self.state,cp(2,"b"*64),"root")

 def test_recovery_advances_independent_transition_head(self):
  self.assertEqual(self.coordinator.recover("north",self.transition),"RECOVERED")
  self.assertEqual(self.anchor.read_head(),self.coordinator.state("north")["transition_sha256"])

 def test_coordinated_database_rollback_is_detected_by_surviving_anchor(self):
  trust_snapshot=str(pathlib.Path(self.tmp.name)/"trust-snapshot.sqlite")
  recovery_snapshot=str(pathlib.Path(self.tmp.name)/"recovery-snapshot.sqlite")
  shutil.copy2(self.trust,trust_snapshot); shutil.copy2(self.recovery,recovery_snapshot)
  self.assertEqual(self.coordinator.recover("north",self.transition),"RECOVERED")
  shutil.copy2(trust_snapshot,self.trust); shutil.copy2(recovery_snapshot,self.recovery)
  with self.assertRaisesRegex(RuntimeError,"differs from independent anchor"):
   self.coordinator.state("north")

 def test_anchor_mismatch_blocks_recovery_before_mutation(self):
  self.anchor.compare_and_set("0"*64,"f"*64)
  before=self.inner.state("north")
  self.assertEqual(self.coordinator.recover("north",self.transition),"ANCHOR_MISMATCH")
  self.assertEqual(self.inner.state("north"),before)

 def test_anchor_unavailable_blocks_recovery_before_mutation(self):
  class Down:
   anchor_id="down"
   def read_head(self): raise OSError("offline")
   def compare_and_set(self,*args): raise OSError("offline")
  anchored=AnchoredWitnessRecovery(self.inner,Down())
  before=self.inner.state("north")
  self.assertEqual(anchored.recover("north",self.transition),"ANCHOR_UNAVAILABLE")
  self.assertEqual(self.inner.state("north"),before)

 def test_post_commit_anchor_failure_strands_state_fail_closed_until_reconciliation(self):
  class FailOnce:
   anchor_id="fail-once"
   def __init__(inner): inner.head="0"*64; inner.fail=True
   def read_head(inner): return inner.head
   def compare_and_set(inner,old,new):
    if inner.fail: inner.fail=False; return False
    if inner.head!=old: return False
    inner.head=new; return True
  anchor=FailOnce()
  anchored=AnchoredWitnessRecovery(self.inner,anchor)
  self.assertEqual(anchored.recover("north",self.transition),"ANCHOR_UPDATE_FAILED")
  with self.assertRaisesRegex(RuntimeError,"differs from independent anchor"):
   anchored.state("north")
  head=anchored.reconcile_anchor("north")
  self.assertEqual(anchor.read_head(),head)
  self.assertEqual(anchored.state("north")["transition_sha256"],head)

 def test_reconcile_refuses_unrelated_external_history(self):
  self.assertEqual(self.inner.recover("north",self.transition),"RECOVERED")
  self.anchor.compare_and_set("0"*64,"f"*64)
  with self.assertRaisesRegex(RuntimeError,"EXPECTED_PREDECESSOR_MISMATCH"):
   self.coordinator.reconcile_anchor("north")
