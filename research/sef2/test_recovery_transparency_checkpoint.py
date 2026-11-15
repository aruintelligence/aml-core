import copy,unittest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from threshold_recovery import POLICY_SCHEMA
from recovery_transparency_checkpoint import build_transparency_checkpoint,verify_transparency_checkpoint

def policy():
 keys={f"authority-{i}":Ed25519PrivateKey.generate() for i in range(4)}
 return {"schema":POLICY_SCHEMA,"policy_id":"recovery-transparency","threshold":3,"max_faults":1,
  "authorities":{name:key.public_key().public_bytes_raw().hex() for name,key in keys.items()},
  "administrative_domains":{name:"domain-"+name for name in keys}}

class RecoveryTransparencyCheckpointTests(unittest.TestCase):
 def setUp(self):
  self.policy=policy()
  self.heads={name:(hex(i+1)[2:]*64)[:64] for i,name in enumerate(sorted(self.policy["authorities"]))}
  self.registry="a"*64
  self.checkpoint=build_transparency_checkpoint(self.policy,7,self.registry,self.heads)
 def test_complete_checkpoint_verifies(self):
  self.assertTrue(verify_transparency_checkpoint(self.checkpoint,self.policy,7,
    self.checkpoint["checkpoint_sha256"]))
 def test_any_authority_head_change_changes_checkpoint(self):
  changed=dict(self.heads); first=sorted(changed)[0]; changed[first]="f"*64
  other=build_transparency_checkpoint(self.policy,7,self.registry,changed)
  self.assertNotEqual(other["checkpoint_sha256"],self.checkpoint["checkpoint_sha256"])
  self.assertFalse(verify_transparency_checkpoint(other,self.policy,7,self.checkpoint["checkpoint_sha256"]))
 def test_policy_registry_head_change_changes_checkpoint(self):
  other=build_transparency_checkpoint(self.policy,7,"b"*64,self.heads)
  self.assertNotEqual(other["checkpoint_sha256"],self.checkpoint["checkpoint_sha256"])
 def test_missing_authority_head_rejected(self):
  heads=dict(self.heads); heads.pop(next(iter(heads)))
  with self.assertRaises(ValueError): build_transparency_checkpoint(self.policy,7,self.registry,heads)
 def test_extra_authority_head_rejected(self):
  heads=dict(self.heads); heads["outsider"]="f"*64
  with self.assertRaises(ValueError): build_transparency_checkpoint(self.policy,7,self.registry,heads)
 def test_policy_substitution_rejected(self):
  changed=copy.deepcopy(self.policy); changed["policy_id"]="other"
  self.assertFalse(verify_transparency_checkpoint(self.checkpoint,changed,7))
 def test_generation_substitution_rejected(self):
  self.assertFalse(verify_transparency_checkpoint(self.checkpoint,self.policy,8))
 def test_checkpoint_hash_tampering_rejected(self):
  changed=copy.deepcopy(self.checkpoint); changed["checkpoint_sha256"]="f"*64
  self.assertFalse(verify_transparency_checkpoint(changed,self.policy,7))
 def test_noncanonical_authority_order_rejected(self):
  changed=copy.deepcopy(self.checkpoint)
  reversed_items=list(changed["payload"]["authority_heads"].items())[::-1]
  changed["payload"]["authority_heads"]={k:v for k,v in reversed_items}
  self.assertFalse(verify_transparency_checkpoint(changed,self.policy,7))
