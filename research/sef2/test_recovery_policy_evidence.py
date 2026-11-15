import copy,pathlib,tempfile,unittest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from threshold_recovery import POLICY_SCHEMA,RecoveryAuthoritySigner
from recovery_policy_rotation import make_policy_rotation
from recovery_policy_registry import RecoveryPolicyRegistry
from recovery_policy_evidence import export_policy_registry_history,verify_policy_registry_history

def keys(prefix): return {f"{prefix}-{i}":Ed25519PrivateKey.generate() for i in range(4)}
def policy(member_keys,name):
 return {"schema":POLICY_SCHEMA,"policy_id":name,"threshold":3,"max_faults":1,
  "authorities":{n:k.public_key().public_bytes_raw().hex() for n,k in member_keys.items()},\n  "administrative_domains":{n:name+"-domain-"+n for n in member_keys}}

class RecoveryPolicyHistoryEvidenceTests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
  self.path=str(pathlib.Path(self.tmp.name)/"registry.sqlite")
  self.old_keys=keys("old"); self.new_keys=keys("new")
  self.old=policy(self.old_keys,"v1"); self.new=policy(self.new_keys,"v2")
  old_signers={n:RecoveryAuthoritySigner(n,k,pathlib.Path(self.tmp.name)/(n+".sqlite")) for n,k in self.old_keys.items()}
  new_signers={n:RecoveryAuthoritySigner(n,k,pathlib.Path(self.tmp.name)/(n+".sqlite")) for n,k in self.new_keys.items()}
  self.registry=RecoveryPolicyRegistry(self.path); self.registry.initialize(self.old)
  rotation=make_policy_rotation(self.old,self.new,2,
   {n:old_signers[n] for n in ("old-0","old-1","old-2")},
   {n:new_signers[n] for n in ("new-0","new-1","new-2")})
  self.assertEqual(self.registry.rotate(self.new,rotation),"ROTATED")
  self.bundle=export_policy_registry_history(self.path)
 def test_exported_registry_history_verifies(self):
  self.assertTrue(verify_policy_registry_history(self.bundle,self.bundle["head_sha256"]))
 def test_wrong_pinned_head_rejected(self):
  self.assertFalse(verify_policy_registry_history(self.bundle,"f"*64))
 def test_truncated_history_rejected(self):
  b=copy.deepcopy(self.bundle); b["events"]=[]; b["head_sha256"]="0"*64
  self.assertFalse(verify_policy_registry_history(b))
 def test_rotation_signature_tampering_rejected(self):
  b=copy.deepcopy(self.bundle); b["events"][0]["rotation"]["outgoing_approval"]["approvals"][0]["signature"]="00"*64
  self.assertFalse(verify_policy_registry_history(b))
 def test_event_hash_tampering_rejected(self):
  b=copy.deepcopy(self.bundle); b["events"][0]["event_sha256"]="f"*64
  self.assertFalse(verify_policy_registry_history(b))
 def test_current_policy_substitution_rejected(self):
  b=copy.deepcopy(self.bundle); b["current_policy"]=self.old; b["current_policy_sha256"]=b["genesis_policy_sha256"]
  self.assertFalse(verify_policy_registry_history(b))
 def test_generation_substitution_rejected(self):
  b=copy.deepcopy(self.bundle); b["generation"]+=1
  self.assertFalse(verify_policy_registry_history(b))
 def test_previous_event_link_tampering_rejected(self):
  b=copy.deepcopy(self.bundle); b["events"][0]["previous_event_sha256"]="f"*64
  self.assertFalse(verify_policy_registry_history(b))
