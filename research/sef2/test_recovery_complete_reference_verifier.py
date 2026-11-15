import copy,hashlib,tempfile,unittest
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from threshold_recovery import RecoveryAuthoritySigner,POLICY_SCHEMA
from recovery_policy_registry import RecoveryPolicyRegistry
from recovery_policy_registry_anchor import make_registry_anchor_payload
from recovery_anchor_quorum import POLICY_SCHEMA as ANCHOR_SCHEMA,RecoveryAnchorWitness,make_anchor_payload,make_anchor_certificate
from recovery_ledger_anchor import CHECKPOINT_SCHEMA
from recovery_complete_reference_verifier import verify_complete_recovery_authorization

def recovery_policy(keys,name):
 return {"schema":POLICY_SCHEMA,"policy_id":name,"threshold":3,"max_faults":1,
  "authorities":{k:v.public_key().public_bytes_raw().hex() for k,v in keys.items()}}
def anchor_policy(keys,name):
 return {"schema":ANCHOR_SCHEMA,"policy_id":name,"threshold":3,"max_faults":1,
  "authorities":{k:v.public_key().public_bytes_raw().hex() for k,v in keys.items()},
  "administrative_domains":{k:"operator-domain-"+k for k in keys}}

class CompleteRecoveryAuthorizationTests(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup); root=Path(self.temp.name)
  self.authorities={f"authority-{i}":Ed25519PrivateKey.generate() for i in range(4)}
  self.policy=recovery_policy(self.authorities,"recovery-current")
  registry=RecoveryPolicyRegistry(str(root/"registry.sqlite")); registry.initialize(self.policy)
  state=registry.state()
  self.payload={"witness_id":"north","generation":3,"previous_state_sha256":"a"*64,"new_key_sha256":"b"*64}
  records=[]
  for aid in ("authority-0","authority-1","authority-2"):
   signer=RecoveryAuthoritySigner(aid,self.authorities[aid],str(root/(aid+".sqlite")))
   signer.approve(self.payload,self.policy); ledger=signer.export_approval_ledger()
   public=self.authorities[aid].public_key().public_bytes_raw().hex()
   cp={"schema":CHECKPOINT_SCHEMA,"authority_id":aid,
    "authority_key_sha256":hashlib.sha256(bytes.fromhex(public)).hexdigest(),
    "sequence":1,"head_hash":ledger["head_sha256"]}
   keys={f"{aid}-anchor-{j}":Ed25519PrivateKey.generate() for j in range(4)}
   apolicy=anchor_policy(keys,aid+"-anchor")
   witnesses={k:RecoveryAnchorWitness(k,v,str(root/(k+".sqlite"))) for k,v in keys.items()}
   ap=make_anchor_payload(cp,1,"0"*64,apolicy)
   cert=make_anchor_certificate(ap,apolicy,{k:witnesses[k] for k in sorted(witnesses)[:3]})
   evidence={"schema":"AML-SEF2-RECOVERY-EVIDENCE-BUNDLE-V1","authority_id":aid,
    "ledger":ledger,"checkpoint":cp,"anchor_payload":ap,"anchor_certificate":cert}
   records.append({"authority_id":aid,"authority_public_key_hex":public,"evidence":evidence,
    "anchor_policy":apolicy,"anchor_sequence":1,"previous_anchor_pin":"0"*64})
  registry_anchor_keys={f"registry-anchor-{i}":Ed25519PrivateKey.generate() for i in range(4)}
  self.registry_anchor_policy=anchor_policy(registry_anchor_keys,"registry-anchor")
  witnesses={k:RecoveryAnchorWitness(k,v,str(root/(k+".sqlite"))) for k,v in registry_anchor_keys.items()}
  rap=make_registry_anchor_payload(state,1,"0"*64,self.registry_anchor_policy)
  rac=make_anchor_certificate(rap,self.registry_anchor_policy,{k:witnesses[k] for k in sorted(witnesses)[:3]})
  self.bundle={"schema":"AML-SEF2-COMPLETE-RECOVERY-AUTHORIZATION-V1",
   "payload":self.payload,"recovery_policy":self.policy,"authority_records":records,
   "registry_state":state,"registry_anchor_payload":rap,"registry_anchor_certificate":rac}
 def check(self,b=None,registry_policy=None):
  return verify_complete_recovery_authorization(b or self.bundle,
   registry_policy or self.registry_anchor_policy,1,"0"*64)
 def test_complete_current_transparent_authorization_accepts(self): self.assertTrue(self.check())
 def test_stale_recovery_policy_rejected(self):
  b=copy.deepcopy(self.bundle); b["recovery_policy"]["policy_id"]="stale"
  self.assertFalse(self.check(b))
 def test_registry_state_policy_substitution_rejected(self):
  b=copy.deepcopy(self.bundle); b["registry_state"]["policy"]["policy_id"]="other"
  self.assertFalse(self.check(b))
 def test_below_threshold_transparent_records_rejected(self):
  b=copy.deepcopy(self.bundle); b["authority_records"]=b["authority_records"][:2]
  self.assertFalse(self.check(b))
 def test_payload_substitution_rejected(self):
  b=copy.deepcopy(self.bundle); b["payload"]["generation"]=4
  self.assertFalse(self.check(b))
 def test_registry_anchor_forgery_rejected(self):
  b=copy.deepcopy(self.bundle); b["registry_anchor_certificate"]["approvals"][0]["signature"]="00"*64
  self.assertFalse(self.check(b))
 def test_registry_anchor_key_overlap_with_authority_anchor_rejected(self):
  p=copy.deepcopy(self.registry_anchor_policy)
  record=self.bundle["authority_records"][0]
  p["authorities"][next(iter(p["authorities"]))]=next(iter(record["anchor_policy"]["authorities"].values()))
  self.assertFalse(self.check(registry_policy=p))
 def test_authority_record_anchor_forgery_rejected(self):
  b=copy.deepcopy(self.bundle); b["authority_records"][0]["evidence"]["anchor_certificate"]["approvals"][0]["signature"]="00"*64
  self.assertFalse(self.check(b))
 def test_duplicate_authority_record_rejected(self):
  b=copy.deepcopy(self.bundle); b["authority_records"][2]=copy.deepcopy(b["authority_records"][1])
  self.assertFalse(self.check(b))
