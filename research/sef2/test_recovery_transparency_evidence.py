import copy,pathlib,tempfile,unittest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from threshold_recovery import POLICY_SCHEMA,RecoveryAuthoritySigner
from recovery_policy_registry import RecoveryPolicyRegistry
from recovery_policy_evidence import export_policy_registry_history
from recovery_target_registry import RecoveryTargetRegistry
from recovery_target_evidence import export_target_registry_history
from recovery_transparency_checkpoint import build_transparency_checkpoint_v2
from recovery_transparency_evidence import verify_recovery_transparency_evidence

def policy(keys):
 return {"schema":POLICY_SCHEMA,"policy_id":"transparency-evidence","threshold":3,"max_faults":1,
  "authorities":{n:k.public_key().public_bytes_raw().hex() for n,k in keys.items()},
  "administrative_domains":{n:"domain-"+n for n in keys}}

class RecoveryTransparencyEvidenceTests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
  self.keys={f"r{i}":Ed25519PrivateKey.generate() for i in range(4)}
  self.policy=policy(self.keys)
  registry_path=pathlib.Path(self.tmp.name)/"policy.sqlite"
  registry=RecoveryPolicyRegistry(registry_path); registry.initialize(self.policy)
  self.policy_history=export_policy_registry_history(registry_path)
  target_path=pathlib.Path(self.tmp.name)/"targets.sqlite"
  target_registry=RecoveryTargetRegistry(target_path); target_registry.initialize(("authority-a","authority-b"))
  self.target_history=export_target_registry_history(target_path,("authority-a","authority-b"))
  self.signers={n:RecoveryAuthoritySigner(n,k,pathlib.Path(self.tmp.name)/(n+".sqlite"))
    for n,k in self.keys.items()}
  payload={"witness_id":"north","generation":1,"previous_state_sha256":"a"*64}
  for signer in self.signers.values(): signer.approve(payload,self.policy)
  self.ledgers={n:s.export_approval_ledger() for n,s in self.signers.items()}
  heads={n:l["head_sha256"] for n,l in self.ledgers.items()}
  self.checkpoint=build_transparency_checkpoint_v2(self.policy,
    self.policy_history["generation"],self.policy_history["head_sha256"],heads,
    self.target_history["generation"],self.target_history["head_sha256"],
    tuple(self.target_history["current_targets"]))
 def check(self,policy_history=None,target_history=None,ledgers=None,checkpoint=None,pin=None):
  c=self.checkpoint if checkpoint is None else checkpoint
  return verify_recovery_transparency_evidence(
    self.policy_history if policy_history is None else policy_history,
    self.target_history if target_history is None else target_history,
    self.ledgers if ledgers is None else ledgers,c,
    c["checkpoint_sha256"] if pin is None else pin)
 def test_complete_histories_recompute_transparency_checkpoint(self): self.assertTrue(self.check())
 def test_policy_history_head_tampering_rejected(self):
  h=copy.deepcopy(self.policy_history); h["head_sha256"]="f"*64
  self.assertFalse(self.check(policy_history=h))
 def test_target_history_head_tampering_rejected(self):
  h=copy.deepcopy(self.target_history); h["head_sha256"]="f"*64
  self.assertFalse(self.check(target_history=h))
 def test_authority_ledger_head_tampering_rejected(self):
  ledgers=copy.deepcopy(self.ledgers); ledgers["r0"]["head_sha256"]="f"*64
  self.assertFalse(self.check(ledgers=ledgers))
 def test_missing_authority_history_rejected(self):
  ledgers=dict(self.ledgers); ledgers.pop("r3")
  self.assertFalse(self.check(ledgers=ledgers))
 def test_checkpoint_substitution_rejected(self):
  c=copy.deepcopy(self.checkpoint); c["payload"]["target_registry_generation"]+=1
  self.assertFalse(self.check(checkpoint=c))
 def test_wrong_externally_pinned_checkpoint_rejected(self): self.assertFalse(self.check(pin="f"*64))
 def test_policy_substitution_inside_history_rejected(self):
  h=copy.deepcopy(self.policy_history); h["current_policy"]["policy_id"]="other"
  self.assertFalse(self.check(policy_history=h))
 def test_target_substitution_inside_history_rejected(self):
  h=copy.deepcopy(self.target_history); h["current_targets"]=["authority-a","authority-c"]
  self.assertFalse(self.check(target_history=h))
