import pathlib,tempfile,unittest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from trust_enrollment import Enrollment,propose
from witness_key_recovery import make_transition
from witness_recovery_enrollment import WitnessRecoveryEnrollment
from anchored_witness_recovery import AnchoredWitnessRecovery
from threshold_recovery import MemoryRecoveryHeadAnchor,QuorumRecoveryHeadAnchor

def pub(k): return k.public_key().public_bytes_raw().hex()
def cp(epoch=1,head="a"*64):
 return {"schema":"AML-SEF2-SIGNED-HISTORY-CHECKPOINT-V1","epoch":epoch,
  "head_hash":head,"count":epoch,"approver_key_id":"c"*64}

class QuorumAnchoredWitnessRecoveryTests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
  trust=str(pathlib.Path(self.tmp.name)/"trust.sqlite")
  recovery=str(pathlib.Path(self.tmp.name)/"recovery.sqlite")
  approver=Ed25519PrivateKey.generate(); self.root=Ed25519PrivateKey.generate()
  self.old=Ed25519PrivateKey.generate(); self.new=Ed25519PrivateKey.generate()
  keys={"authority":pub(Ed25519PrivateKey.generate()),
   "provider":pub(Ed25519PrivateKey.generate()),"witness":pub(self.old)}
  enrollment=Enrollment(trust,approver.public_key()); enrollment.accept(propose(approver,1,keys))
  self.inner=WitnessRecoveryEnrollment(trust,recovery,self.root.public_key(),"root")
  self.replicas=[MemoryRecoveryHeadAnchor(f"recovery-anchor-{i}") for i in range(4)]
  self.quorum=QuorumRecoveryHeadAnchor(self.replicas,3,1)
  self.coordinator=AnchoredWitnessRecovery(self.inner,self.quorum)
  self.state=self.coordinator.initialize("north",cp())
  self.transition=make_transition(self.root,self.new,"north",self.state,cp(2,"b"*64),"root")

 def test_three_of_four_recovery_head_quorum_advances(self):
  self.assertEqual(self.coordinator.recover("north",self.transition),"RECOVERED")
  self.assertEqual(self.quorum.read_head(),self.coordinator.state("north")["transition_sha256"])

 def test_one_unavailable_anchor_does_not_block_recovery(self):
  class Down:
   anchor_id="recovery-down"
   def read_head(self): raise OSError("offline")
   def compare_and_set(self,*args): raise OSError("offline")
  quorum=QuorumRecoveryHeadAnchor(self.replicas[:3]+[Down()],3,1)
  coordinator=AnchoredWitnessRecovery(self.inner,quorum)
  self.assertEqual(coordinator.recover("north",self.transition),"RECOVERED")
  self.assertEqual(quorum.read_head(),coordinator.state("north")["transition_sha256"])

 def test_two_two_partition_blocks_recovery_before_mutation(self):
  for replica,head in zip(self.replicas,("a"*64,"a"*64,"b"*64,"b"*64)):
   replica.compare_and_set("0"*64,head)
  before=self.inner.state("north")
  self.assertEqual(self.coordinator.recover("north",self.transition),"ANCHOR_UNAVAILABLE")
  self.assertEqual(self.inner.state("north"),before)

 def test_one_dissenting_anchor_is_outvoted(self):
  self.replicas[0].compare_and_set("0"*64,"f"*64)
  self.assertEqual(self.quorum.read_head(),"0"*64)
  self.assertEqual(self.coordinator.recover("north",self.transition),"RECOVERED")

 def test_conflicting_quorum_head_prevents_state_read(self):
  self.assertEqual(self.coordinator.recover("north",self.transition),"RECOVERED")
  current=self.quorum.read_head()
  self.replicas[0]._head="f"*64
  self.replicas[1]._head="f"*64
  with self.assertRaises(RuntimeError):
   self.coordinator.state("north")
  self.replicas[0]._head=current
  self.replicas[1]._head=current
  self.assertEqual(self.coordinator.state("north")["transition_sha256"],current)
