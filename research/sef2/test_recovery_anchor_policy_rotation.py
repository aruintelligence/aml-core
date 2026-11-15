import copy,tempfile,unittest
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from threshold_recovery import RecoveryAuthoritySigner
from recovery_anchor_quorum import POLICY_SCHEMA
from recovery_anchor_policy_rotation import make_anchor_policy_rotation,verify_anchor_policy_rotation

def policy(keys,name):
 return {"schema":POLICY_SCHEMA,"policy_id":name,"threshold":3,"max_faults":1,
  "authorities":{k:v.public_key().public_bytes_raw().hex() for k,v in keys.items()},
  "administrative_domains":{k:name+"-"+k for k in keys}}
class AnchorPolicyRotationTests(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup); root=Path(self.temp.name)
  self.old_keys={f"old-{i}":Ed25519PrivateKey.generate() for i in range(4)}
  self.new_keys={f"new-{i}":Ed25519PrivateKey.generate() for i in range(4)}
  self.old=policy(self.old_keys,"anchor-v1"); self.new=policy(self.new_keys,"anchor-v2")
  self.old_signers={k:RecoveryAuthoritySigner(k,v,str(root/(k+".sqlite"))) for k,v in self.old_keys.items()}
  self.new_signers={k:RecoveryAuthoritySigner(k,v,str(root/(k+".sqlite"))) for k,v in self.new_keys.items()}
  self.rotation=make_anchor_policy_rotation(self.old,self.new,2,"a"*64,
   {k:self.old_signers[k] for k in ("old-0","old-1","old-2")},
   {k:self.new_signers[k] for k in ("new-0","new-1","new-2")})
 def check(self,r=None,old=None,new=None,g=2,pin="a"*64):
  return verify_anchor_policy_rotation(old or self.old,new or self.new,r or self.rotation,g,pin)
 def test_dual_consent_rotation_accepts(self): self.assertTrue(self.check())
 def test_outgoing_quorum_shortfall_rejected(self):
  r=copy.deepcopy(self.rotation); r["outgoing_approval"]["approvals"]=r["outgoing_approval"]["approvals"][:2]
  self.assertFalse(self.check(r))
 def test_incoming_quorum_shortfall_rejected(self):
  r=copy.deepcopy(self.rotation); r["incoming_acceptance"]["approvals"]=r["incoming_acceptance"]["approvals"][:2]
  self.assertFalse(self.check(r))
 def test_wrong_generation_rejected(self): self.assertFalse(self.check(g=3))
 def test_wrong_previous_anchor_pin_rejected(self): self.assertFalse(self.check(pin="f"*64))
 def test_payload_substitution_rejected(self):
  r=copy.deepcopy(self.rotation); r["payload"]["next_policy_sha256"]="f"*64
  self.assertFalse(self.check(r))
 def test_outgoing_signature_forgery_rejected(self):
  r=copy.deepcopy(self.rotation); r["outgoing_approval"]["approvals"][0]["signature"]="00"*64
  self.assertFalse(self.check(r))
 def test_incoming_signature_forgery_rejected(self):
  r=copy.deepcopy(self.rotation); r["incoming_acceptance"]["approvals"][0]["signature"]="00"*64
  self.assertFalse(self.check(r))
 def test_reused_anchor_key_between_councils_rejected(self):
  changed=copy.deepcopy(self.new)
  changed["authorities"]["new-0"]=self.old["authorities"]["old-0"]
  with self.assertRaises(ValueError):
   make_anchor_policy_rotation(self.old,changed,2,"a"*64,
    {k:self.old_signers[k] for k in ("old-0","old-1","old-2")},
    {k:self.new_signers[k] for k in ("new-0","new-1","new-2")})
 def test_same_policy_id_rejected(self):
  changed=copy.deepcopy(self.new); changed["policy_id"]=self.old["policy_id"]
  self.assertFalse(self.check(new=changed))
