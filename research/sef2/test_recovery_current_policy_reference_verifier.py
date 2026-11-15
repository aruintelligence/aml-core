import copy,hashlib,tempfile,unittest
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from threshold_recovery import RecoveryAuthoritySigner,POLICY_SCHEMA
from recovery_policy_registry import RecoveryPolicyRegistry
from recovery_policy_registry_anchor import make_registry_anchor_payload
from recovery_anchor_quorum import (POLICY_SCHEMA as ANCHOR_SCHEMA,RecoveryAnchorWitness,
    make_anchor_payload,make_anchor_certificate)
from recovery_ledger_anchor import CHECKPOINT_SCHEMA
from recovery_current_policy_reference_verifier import verify_current_recovery_evidence

def make_policy(keys,name):
 return {"schema":POLICY_SCHEMA,"policy_id":name,"threshold":3,"max_faults":1,
  "authorities":{k:v.public_key().public_bytes_raw().hex() for k,v in keys.items()}}
def make_anchor_policy(keys,name):
 return {"schema":ANCHOR_SCHEMA,"policy_id":name,"threshold":3,"max_faults":1,
  "authorities":{k:v.public_key().public_bytes_raw().hex() for k,v in keys.items()}}

class CurrentRecoveryPolicyVerifierTests(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup); root=Path(self.temp.name)
  self.recovery_keys={f"r{i}":Ed25519PrivateKey.generate() for i in range(4)}
  self.policy=make_policy(self.recovery_keys,"recovery-v1")
  self.registry=RecoveryPolicyRegistry(str(root/"registry.sqlite")); self.registry.initialize(self.policy)
  self.registry_state=self.registry.state()
  self.authority_id="r0"; self.authority=self.recovery_keys[self.authority_id]
  self.signer=RecoveryAuthoritySigner(self.authority_id,self.authority,str(root/"authority.sqlite"))
  payload={"witness_id":"north","generation":1,"previous_state_sha256":"a"*64}
  self.signer.approve(payload,self.policy)
  ledger=self.signer.export_approval_ledger()
  pub=self.authority.public_key().public_bytes_raw().hex(); self.public=pub
  fp=hashlib.sha256(bytes.fromhex(pub)).hexdigest()
  checkpoint={"schema":CHECKPOINT_SCHEMA,"authority_id":self.authority_id,
   "authority_key_sha256":fp,"sequence":1,"head_hash":ledger["head_sha256"]}
  self.authority_anchor_keys={f"aa{i}":Ed25519PrivateKey.generate() for i in range(4)}
  self.authority_anchor_policy=make_anchor_policy(self.authority_anchor_keys,"authority-anchor")
  aa={k:RecoveryAnchorWitness(k,v,str(root/(k+".sqlite"))) for k,v in self.authority_anchor_keys.items()}
  ap=make_anchor_payload(checkpoint,1,"0"*64,self.authority_anchor_policy)
  ac=make_anchor_certificate(ap,self.authority_anchor_policy,{k:aa[k] for k in ("aa0","aa1","aa2")})
  self.recovery_evidence={"schema":"AML-SEF2-RECOVERY-EVIDENCE-BUNDLE-V1","authority_id":self.authority_id,
   "ledger":ledger,"checkpoint":checkpoint,"anchor_payload":ap,"anchor_certificate":ac}
  self.registry_anchor_keys={f"ra{i}":Ed25519PrivateKey.generate() for i in range(4)}
  self.registry_anchor_policy=make_anchor_policy(self.registry_anchor_keys,"registry-anchor")
  ra={k:RecoveryAnchorWitness(k,v,str(root/(k+".sqlite"))) for k,v in self.registry_anchor_keys.items()}
  rap=make_registry_anchor_payload(self.registry_state,1,"0"*64,self.registry_anchor_policy)
  rac=make_anchor_certificate(rap,self.registry_anchor_policy,{k:ra[k] for k in ("ra0","ra1","ra2")})
  self.bundle={"schema":"AML-SEF2-CURRENT-RECOVERY-EVIDENCE-V1",
   "recovery_evidence":self.recovery_evidence,"registry_state":self.registry_state,
   "registry_anchor_payload":rap,"registry_anchor_certificate":rac}
 def check(self,b=None):
  return verify_current_recovery_evidence(b or self.bundle,self.public,
   self.authority_anchor_policy,1,"0"*64,self.registry_anchor_policy,1,"0"*64)
 def test_current_policy_bound_recovery_accepts(self): self.assertTrue(self.check())
 def test_old_policy_digest_in_latest_approval_rejected(self):
  b=copy.deepcopy(self.bundle); b["recovery_evidence"]["ledger"]["events"][-1]["policy_sha256"]="f"*64
  self.assertFalse(self.check(b))
 def test_registry_policy_substitution_rejected(self):
  b=copy.deepcopy(self.bundle); b["registry_state"]["policy"]["policy_id"]="other"
  self.assertFalse(self.check(b))
 def test_registry_anchor_signature_forgery_rejected(self):
  b=copy.deepcopy(self.bundle); b["registry_anchor_certificate"]["approvals"][0]["signature"]="00"*64
  self.assertFalse(self.check(b))
 def test_registry_head_substitution_rejected(self):
  b=copy.deepcopy(self.bundle); b["registry_state"]["head_sha256"]="f"*64
  self.assertFalse(self.check(b))
 def test_recovery_evidence_still_independently_verified(self):
  b=copy.deepcopy(self.bundle); b["recovery_evidence"]["checkpoint"]["head_hash"]="f"*64
  self.assertFalse(self.check(b))
 def test_empty_ledger_rejected(self):
  b=copy.deepcopy(self.bundle); b["recovery_evidence"]["ledger"]["events"]=[]
  self.assertFalse(self.check(b))

 def test_same_anchor_policy_for_both_planes_rejected(self):
  self.assertFalse(verify_current_recovery_evidence(self.bundle,self.public,
   self.authority_anchor_policy,1,"0"*64,self.authority_anchor_policy,1,"0"*64))
 def test_overlapping_anchor_key_rejected(self):
  p=copy.deepcopy(self.registry_anchor_policy)
  first_registry=sorted(p["authorities"])[0]
  first_authority=sorted(self.authority_anchor_policy["authorities"])[0]
  p["authorities"][first_registry]=self.authority_anchor_policy["authorities"][first_authority]
  self.assertFalse(verify_current_recovery_evidence(self.bundle,self.public,
   self.authority_anchor_policy,1,"0"*64,p,1,"0"*64))

 def test_standalone_cli_accepts_current_policy_bound_bundle(self):
  import json,subprocess,sys
  from pathlib import Path
  bundle=Path(self.temp.name)/"current-recovery.json"
  authority_policy=Path(self.temp.name)/"authority-anchor-policy.json"
  registry_policy=Path(self.temp.name)/"registry-anchor-policy.json"
  bundle.write_text(json.dumps(self.bundle),encoding="utf-8")
  authority_policy.write_text(json.dumps(self.authority_anchor_policy),encoding="utf-8")
  registry_policy.write_text(json.dumps(self.registry_anchor_policy),encoding="utf-8")
  script=Path(__file__).with_name("recovery_current_policy_reference_verifier.py")
  result=subprocess.run([sys.executable,str(script),str(bundle),
    "--authority-public-key",self.public,
    "--authority-anchor-policy",str(authority_policy),
    "--authority-anchor-sequence","1",
    "--authority-previous-anchor-pin","0"*64,
    "--registry-anchor-policy",str(registry_policy),
    "--registry-anchor-sequence","1",
    "--registry-previous-anchor-pin","0"*64],
    capture_output=True,text=True,check=False)
  self.assertEqual(result.returncode,0,result.stdout+result.stderr)
  self.assertIn("independently anchored current policy",result.stdout)

 def test_standalone_cli_rejects_duplicate_json_keys(self):
  import json,subprocess,sys
  from pathlib import Path
  raw=json.dumps(self.bundle).replace('"schema":', '"schema":"shadow","schema":',1)
  bundle=Path(self.temp.name)/"duplicate.json"
  authority_policy=Path(self.temp.name)/"authority-anchor-policy-dup.json"
  registry_policy=Path(self.temp.name)/"registry-anchor-policy-dup.json"
  bundle.write_text(raw,encoding="utf-8")
  authority_policy.write_text(json.dumps(self.authority_anchor_policy),encoding="utf-8")
  registry_policy.write_text(json.dumps(self.registry_anchor_policy),encoding="utf-8")
  script=Path(__file__).with_name("recovery_current_policy_reference_verifier.py")
  result=subprocess.run([sys.executable,str(script),str(bundle),
    "--authority-public-key",self.public,
    "--authority-anchor-policy",str(authority_policy),
    "--authority-anchor-sequence","1","--authority-previous-anchor-pin","0"*64,
    "--registry-anchor-policy",str(registry_policy),
    "--registry-anchor-sequence","1","--registry-previous-anchor-pin","0"*64],
    capture_output=True,text=True,check=False)
  self.assertEqual(result.returncode,2)
