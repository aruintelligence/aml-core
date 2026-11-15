import pathlib,shutil,tempfile,unittest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from threshold_recovery import POLICY_SCHEMA,MemoryRecoveryHeadAnchor,QuorumRecoveryHeadAnchor
from recovery_transparency_checkpoint import build_transparency_checkpoint_v3
from recovery_transparency_log import RecoveryTransparencyLog

def policy():
 keys={f"r{i}":Ed25519PrivateKey.generate() for i in range(4)}
 return {"schema":POLICY_SCHEMA,"policy_id":"transparency-log","threshold":3,"max_faults":1,
  "authorities":{n:k.public_key().public_bytes_raw().hex() for n,k in keys.items()},
  "administrative_domains":{n:"domain-"+n for n in keys}}
def heads(policy):
 return {n:(hex(i+1)[2:]*64)[:64] for i,n in enumerate(sorted(policy["authorities"]))}

class RecoveryTransparencyLogTests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
  self.policy=policy(); self.targets=("authority-a","authority-b"); self.heads=heads(self.policy)
  self.anchor=MemoryRecoveryHeadAnchor("transparency-anchor")
  self.path=pathlib.Path(self.tmp.name)/"transparency.sqlite"
  self.log=RecoveryTransparencyLog(self.path,self.anchor)
  self.first=build_transparency_checkpoint_v3(self.policy,1,"a"*64,self.heads,1,"b"*64,
   self.targets,1,"0"*64)
 def test_publish_advances_local_and_external_head(self):
  self.assertEqual(self.log.append(self.first,self.policy,self.targets),"PUBLISHED")
  self.assertEqual(self.log.state(),{"sequence":1,"head_sha256":self.first["checkpoint_sha256"]})
  self.assertEqual(self.anchor.read_head(),self.first["checkpoint_sha256"])
 def test_replay_is_rejected(self):
  self.assertEqual(self.log.append(self.first,self.policy,self.targets),"PUBLISHED")
  self.assertEqual(self.log.append(self.first,self.policy,self.targets),"INVALID_CHECKPOINT")
 def test_local_database_rollback_behind_anchor_is_detected(self):
  snapshot=pathlib.Path(self.tmp.name)/"before.sqlite"; shutil.copy2(self.path,snapshot)
  self.log.append(self.first,self.policy,self.targets); shutil.copy2(snapshot,self.path)
  with self.assertRaises(ValueError): self.log.state()
 def test_anchor_mismatch_blocks_append_before_mutation(self):
  self.anchor.compare_and_set("0"*64,"f"*64)
  self.assertEqual(self.log.append(self.first,self.policy,self.targets),"ANCHOR_MISMATCH")
  self.assertEqual(self.log._local_state()["sequence"],0)
 def test_post_commit_anchor_failure_can_be_reconciled(self):
  class FailOnce:
   anchor_id="fail-once"
   def __init__(self): self.head="0"*64; self.fail=True
   def read_head(self): return self.head
   def compare_and_set(self,old,new):
    if self.fail: self.fail=False; return False
    if self.head!=old: return False
    self.head=new; return True
  anchor=FailOnce(); log=RecoveryTransparencyLog(pathlib.Path(self.tmp.name)/"fail.sqlite",anchor)
  self.assertEqual(log.append(self.first,self.policy,self.targets),"ANCHOR_UPDATE_FAILED")
  with self.assertRaises(ValueError): log.state()
  self.assertEqual(log.reconcile_anchor(),self.first["checkpoint_sha256"])
  self.assertEqual(log.state()["sequence"],1)
 def test_three_of_four_anchor_quorum_publishes(self):
  replicas=[MemoryRecoveryHeadAnchor(f"t{i}") for i in range(4)]
  quorum=QuorumRecoveryHeadAnchor(replicas,3,1)
  log=RecoveryTransparencyLog(pathlib.Path(self.tmp.name)/"quorum.sqlite",quorum)
  self.assertEqual(log.append(self.first,self.policy,self.targets),"PUBLISHED")
  self.assertEqual(quorum.read_head(),self.first["checkpoint_sha256"])
 def test_two_two_anchor_partition_blocks_publication(self):
  replicas=[MemoryRecoveryHeadAnchor(f"p{i}") for i in range(4)]
  for replica,head in zip(replicas,("a"*64,"a"*64,"b"*64,"b"*64)):
   replica.compare_and_set("0"*64,head)
  log=RecoveryTransparencyLog(pathlib.Path(self.tmp.name)/"partition.sqlite",
    QuorumRecoveryHeadAnchor(replicas,3,1))
  self.assertEqual(log.append(self.first,self.policy,self.targets),"ANCHOR_UNAVAILABLE")
  self.assertEqual(log._local_state()["sequence"],0)
