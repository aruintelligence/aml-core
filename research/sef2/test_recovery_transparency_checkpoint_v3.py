import copy,unittest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from threshold_recovery import POLICY_SCHEMA
from recovery_transparency_checkpoint import (build_transparency_checkpoint_v3,
 verify_transparency_checkpoint_v3,verify_transparency_chain)

def policy(name):
 keys={f"{name}-authority-{i}":Ed25519PrivateKey.generate() for i in range(4)}
 return {"schema":POLICY_SCHEMA,"policy_id":name,"threshold":3,"max_faults":1,
  "authorities":{n:k.public_key().public_bytes_raw().hex() for n,k in keys.items()},
  "administrative_domains":{n:"domain-"+n for n in keys}}

class RecoveryTransparencyCheckpointV3Tests(unittest.TestCase):
 def setUp(self):
  self.policy=policy("p1")
  self.targets=("authority-a","authority-b")
  self.heads={n:(hex(i+1)[2:]*64)[:64] for i,n in enumerate(sorted(self.policy["authorities"]))}
  self.first=build_transparency_checkpoint_v3(self.policy,1,"a"*64,self.heads,1,"b"*64,
    self.targets,1,"0"*64)
  self.second=build_transparency_checkpoint_v3(self.policy,1,"a"*64,self.heads,2,"c"*64,
    ("authority-a","authority-c"),2,self.first["checkpoint_sha256"])
 def test_single_v3_checkpoint_verifies(self):
  self.assertTrue(verify_transparency_checkpoint_v3(self.first,self.policy,self.targets,1,"0"*64,
    1,1,self.first["checkpoint_sha256"]))
 def test_two_checkpoint_chain_verifies(self):
  self.assertTrue(verify_transparency_chain([self.first,self.second],
    [self.policy,self.policy],[self.targets,("authority-a","authority-c")],
    self.second["checkpoint_sha256"]))
 def test_wrong_predecessor_rejected(self):
  self.assertFalse(verify_transparency_checkpoint_v3(self.second,self.policy,
    ("authority-a","authority-c"),2,"f"*64,1,2))
 def test_sequence_skip_rejected(self):
  self.assertFalse(verify_transparency_checkpoint_v3(self.second,self.policy,
    ("authority-a","authority-c"),3,self.first["checkpoint_sha256"],1,2))
 def test_chain_reordering_rejected(self):
  self.assertFalse(verify_transparency_chain([self.second,self.first],
    [self.policy,self.policy],[("authority-a","authority-c"),self.targets]))
 def test_chain_truncation_rejected_by_pinned_head(self):
  self.assertFalse(verify_transparency_chain([self.first],[self.policy],[self.targets],
    self.second["checkpoint_sha256"]))
 def test_policy_generation_rollback_rejected_across_chain(self):
  first=build_transparency_checkpoint_v3(self.policy,2,"a"*64,self.heads,1,"b"*64,
    self.targets,1,"0"*64)
  second=build_transparency_checkpoint_v3(self.policy,1,"a"*64,self.heads,2,"c"*64,
    self.targets,2,first["checkpoint_sha256"])
  self.assertFalse(verify_transparency_chain([first,second],[self.policy,self.policy],
    [self.targets,self.targets]))
 def test_target_generation_rollback_rejected_across_chain(self):
  first=build_transparency_checkpoint_v3(self.policy,1,"a"*64,self.heads,2,"b"*64,
    self.targets,1,"0"*64)
  second=build_transparency_checkpoint_v3(self.policy,1,"a"*64,self.heads,1,"c"*64,
    self.targets,2,first["checkpoint_sha256"])
  self.assertFalse(verify_transparency_chain([first,second],[self.policy,self.policy],
    [self.targets,self.targets]))
 def test_checkpoint_payload_tampering_rejected(self):
  c=copy.deepcopy(self.first); c["payload"]["policy_registry_head_sha256"]="f"*64
  self.assertFalse(verify_transparency_checkpoint_v3(c,self.policy,self.targets,1,"0"*64,1,1))
 def test_v3_hash_tampering_rejected(self):
  c=copy.deepcopy(self.first); c["checkpoint_sha256"]="f"*64
  self.assertFalse(verify_transparency_checkpoint_v3(c,self.policy,self.targets,1,"0"*64,1,1))
