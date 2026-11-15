import copy,pathlib,tempfile,unittest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from threshold_recovery import POLICY_SCHEMA,RecoveryAuthoritySigner
from recovery_target_registry import RecoveryTargetRegistry,make_target_change
from recovery_target_evidence import export_target_registry_history,verify_target_registry_history

def policy(keys):
 return {"schema":POLICY_SCHEMA,"policy_id":"target-history","threshold":3,"max_faults":1,
  "authorities":{n:k.public_key().public_bytes_raw().hex() for n,k in keys.items()},
  "administrative_domains":{n:"domain-"+n for n in keys}}

class RecoveryTargetHistoryEvidenceTests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
  self.keys={f"r{i}":Ed25519PrivateKey.generate() for i in range(4)}
  self.policy=policy(self.keys)
  self.signers={n:RecoveryAuthoritySigner(n,k,pathlib.Path(self.tmp.name)/(n+".sqlite"))
    for n,k in self.keys.items()}
  self.quorum={n:self.signers[n] for n in ("r0","r1","r2")}
  self.path=pathlib.Path(self.tmp.name)/"targets.sqlite"
  self.initial=("authority-a","authority-b")
  self.registry=RecoveryTargetRegistry(self.path); self.registry.initialize(self.initial)
  state=self.registry.state()
  change=make_target_change(state["targets"],2,state["head_sha256"],
    ["authority-c"],["authority-b"],self.policy,self.quorum)
  self.assertEqual(self.registry.apply(change,self.policy),"UPDATED")
  self.bundle=export_target_registry_history(self.path,self.initial)
 def test_complete_target_history_verifies(self):
  self.assertTrue(verify_target_registry_history(self.bundle,self.policy,self.bundle["head_sha256"]))
 def test_wrong_pinned_head_rejected(self):
  self.assertFalse(verify_target_registry_history(self.bundle,self.policy,"f"*64))
 def test_truncated_history_rejected(self):
  b=copy.deepcopy(self.bundle); b["events"]=[]; b["head_sha256"]="0"*64
  self.assertFalse(verify_target_registry_history(b,self.policy))
 def test_change_signature_tampering_rejected(self):
  b=copy.deepcopy(self.bundle); b["events"][0]["change"]["approval"]["approvals"][0]["signature"]="00"*64
  self.assertFalse(verify_target_registry_history(b,self.policy))
 def test_event_hash_tampering_rejected(self):
  b=copy.deepcopy(self.bundle); b["events"][0]["event_sha256"]="f"*64
  self.assertFalse(verify_target_registry_history(b,self.policy))
 def test_current_target_substitution_rejected(self):
  b=copy.deepcopy(self.bundle); b["current_targets"]=["authority-a","authority-d"]
  self.assertFalse(verify_target_registry_history(b,self.policy))
 def test_generation_substitution_rejected(self):
  b=copy.deepcopy(self.bundle); b["generation"]+=1
  self.assertFalse(verify_target_registry_history(b,self.policy))
 def test_initial_target_omission_rejected(self):
  b=copy.deepcopy(self.bundle); b["initial_targets"]=["authority-a"]
  self.assertFalse(verify_target_registry_history(b,self.policy))
 def test_policy_substitution_rejected(self):
  p=copy.deepcopy(self.policy); p["policy_id"]="other"
  self.assertFalse(verify_target_registry_history(self.bundle,p))
