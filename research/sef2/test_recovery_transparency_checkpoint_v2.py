import copy,unittest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from threshold_recovery import POLICY_SCHEMA
from recovery_transparency_checkpoint import build_transparency_checkpoint_v2,verify_transparency_checkpoint_v2,verify_transparency_checkpoint
def policy():
 keys={f"authority-{i}":Ed25519PrivateKey.generate() for i in range(4)}
 return {"schema":POLICY_SCHEMA,"policy_id":"recovery-transparency-v2","threshold":3,"max_faults":1,
  "authorities":{n:k.public_key().public_bytes_raw().hex() for n,k in keys.items()},
  "administrative_domains":{n:"domain-"+n for n in keys}}
class RecoveryTransparencyCheckpointV2Tests(unittest.TestCase):
 def setUp(self):
  self.policy=policy(); self.targets=("authority-a","authority-b")
  self.heads={n:(hex(i+1)[2:]*64)[:64] for i,n in enumerate(sorted(self.policy["authorities"]))}
  self.checkpoint=build_transparency_checkpoint_v2(self.policy,7,"a"*64,self.heads,3,"b"*64,self.targets)
 def check(self,c=None,targets=None,pg=7,tg=3,pin=None,policy_value=None):
  c=self.checkpoint if c is None else c
  return verify_transparency_checkpoint_v2(c,self.policy if policy_value is None else policy_value,
   self.targets if targets is None else targets,pg,tg,c["checkpoint_sha256"] if pin is None else pin)
 def test_complete_v2_checkpoint_verifies(self): self.assertTrue(self.check())
 def test_target_registry_head_change_changes_root(self):
  c=build_transparency_checkpoint_v2(self.policy,7,"a"*64,self.heads,3,"c"*64,self.targets)
  self.assertNotEqual(c["checkpoint_sha256"],self.checkpoint["checkpoint_sha256"])
  self.assertFalse(self.check(c,pin=self.checkpoint["checkpoint_sha256"]))
 def test_tracked_target_change_changes_root(self):
  c=build_transparency_checkpoint_v2(self.policy,7,"a"*64,self.heads,3,"b"*64,("authority-a","authority-c"))
  self.assertNotEqual(c["checkpoint_sha256"],self.checkpoint["checkpoint_sha256"])
 def test_wrong_target_generation_rejected(self): self.assertFalse(self.check(tg=4))
 def test_wrong_policy_generation_rejected(self): self.assertFalse(self.check(pg=8))
 def test_wrong_external_checkpoint_pin_rejected(self): self.assertFalse(self.check(pin="f"*64))
 def test_target_set_substitution_rejected(self): self.assertFalse(self.check(targets=("authority-a","authority-c")))
 def test_target_omission_rejected(self): self.assertFalse(self.check(targets=("authority-a",)))
 def test_target_order_is_canonical(self):
  with self.assertRaises(ValueError):
   build_transparency_checkpoint_v2(self.policy,7,"a"*64,self.heads,3,"b"*64,("authority-b","authority-a"))
 def test_authority_head_change_rejected_under_old_pin(self):
  heads=dict(self.heads); heads[sorted(heads)[0]]="f"*64
  c=build_transparency_checkpoint_v2(self.policy,7,"a"*64,heads,3,"b"*64,self.targets)
  self.assertFalse(self.check(c,pin=self.checkpoint["checkpoint_sha256"]))
 def test_policy_substitution_rejected(self):
  p=copy.deepcopy(self.policy); p["policy_id"]="other"; self.assertFalse(self.check(policy_value=p))
 def test_v1_verifier_does_not_accept_v2_schema(self): self.assertFalse(verify_transparency_checkpoint(self.checkpoint,self.policy,7))
 def test_tampered_checkpoint_hash_rejected(self):
  c=copy.deepcopy(self.checkpoint); c["checkpoint_sha256"]="f"*64
  self.assertFalse(self.check(c,pin="f"*64))
