import pathlib,tempfile,unittest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from threshold_recovery import MemoryRecoveryHeadAnchor,QuorumRecoveryHeadAnchor,RecoveryAuthoritySigner,POLICY_SCHEMA
from recovery_policy_rotation import make_policy_rotation
from recovery_policy_registry import RecoveryPolicyRegistry

def keys(prefix):
 return {f"{prefix}-{i}":Ed25519PrivateKey.generate() for i in range(4)}
def policy(member_keys,name):
 return {"schema":POLICY_SCHEMA,"policy_id":name,"threshold":3,"max_faults":1,
  "authorities":{k:v.public_key().public_bytes_raw().hex() for k,v in member_keys.items()},
  "administrative_domains":{k:name+"-domain-"+k for k in member_keys}}

class QuorumAnchoredRecoveryPolicyRegistryTests(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
  self.path=str(pathlib.Path(self.temp.name)/"quorum-policy.sqlite")
  self.replicas=[MemoryRecoveryHeadAnchor(f"policy-anchor-{i}") for i in range(4)]
  self.anchor=QuorumRecoveryHeadAnchor(self.replicas,3,1)
  self.old_keys=keys("qold"); self.new_keys=keys("qnew")
  self.old=policy(self.old_keys,"quorum-v1"); self.new=policy(self.new_keys,"quorum-v2")
  self.old_signers={k:RecoveryAuthoritySigner(k,v,str(pathlib.Path(self.temp.name)/(k+".sqlite"))) for k,v in self.old_keys.items()}
  self.new_signers={k:RecoveryAuthoritySigner(k,v,str(pathlib.Path(self.temp.name)/(k+".sqlite"))) for k,v in self.new_keys.items()}
  self.registry=RecoveryPolicyRegistry(self.path,self.anchor); self.registry.initialize(self.old)
  self.rotation=make_policy_rotation(self.old,self.new,2,
   {k:self.old_signers[k] for k in ("qold-0","qold-1","qold-2")},
   {k:self.new_signers[k] for k in ("qnew-0","qnew-1","qnew-2")})
 def test_three_of_four_anchor_quorum_pins_policy_rotation(self):
  self.assertEqual(self.registry.rotate(self.new,self.rotation),"ROTATED")
  self.assertEqual(self.anchor.read_head(),self.registry.state()["head_sha256"])
 def test_one_anchor_unavailable_does_not_block_policy_rotation(self):
  class Down:
   anchor_id="policy-down"
   def read_head(self): raise OSError("offline")
   def compare_and_set(self,*args): raise OSError("offline")
  anchor=QuorumRecoveryHeadAnchor(self.replicas[:3]+[Down()],3,1)
  path=str(pathlib.Path(self.temp.name)/"one-down.sqlite")
  registry=RecoveryPolicyRegistry(path,anchor); registry.initialize(self.old)
  self.assertEqual(registry.rotate(self.new,self.rotation),"ROTATED")
  self.assertEqual(anchor.read_head(),registry.state()["head_sha256"])
 def test_two_two_anchor_partition_blocks_policy_rotation(self):
  for replica,head in zip(self.replicas,("a"*64,"a"*64,"b"*64,"b"*64)):
   replica.compare_and_set("0"*64,head)
  before=self.registry._local_state()
  self.assertEqual(self.registry.rotate(self.new,self.rotation),"ANCHOR_UNAVAILABLE")
  self.assertEqual(self.registry._local_state(),before)
 def test_one_dissenting_anchor_is_outvoted_by_three_consistent_anchors(self):
  self.replicas[0].compare_and_set("0"*64,"f"*64)
  self.assertEqual(self.anchor.read_head(),"0"*64)
  self.assertEqual(self.registry.rotate(self.new,self.rotation),"ROTATED")
  self.assertEqual(self.anchor.read_head(),self.registry.state()["head_sha256"])
 def test_policy_registry_rollback_behind_anchor_quorum_is_detected(self):
  import shutil
  snapshot=str(pathlib.Path(self.temp.name)/"snapshot.sqlite"); shutil.copy2(self.path,snapshot)
  self.assertEqual(self.registry.rotate(self.new,self.rotation),"ROTATED")
  shutil.copy2(snapshot,self.path)
  with self.assertRaises(ValueError):
   self.registry.state()
  self.assertFalse(self.registry.verify_history())
