import copy,hashlib,tempfile,unittest
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from threshold_recovery import RecoveryAuthoritySigner,POLICY_SCHEMA
from recovery_anchor_quorum import POLICY_SCHEMA as ANCHOR_SCHEMA,RecoveryAnchorWitness,make_anchor_payload,make_anchor_certificate
from recovery_ledger_anchor import CHECKPOINT_SCHEMA
from recovery_quorum_transparency_verifier import verify_transparent_recovery_quorum

def policy(keys,name):
 return {"schema":POLICY_SCHEMA,"policy_id":name,"threshold":3,"max_faults":1,
  "authorities":{k:v.public_key().public_bytes_raw().hex() for k,v in keys.items()},}
def anchor_policy(keys,name):
 return {"schema":ANCHOR_SCHEMA,"policy_id":name,"threshold":3,"max_faults":1,
  "authorities":{k:v.public_key().public_bytes_raw().hex() for k,v in keys.items()},
  "administrative_domains":{k:"operator-domain-"+k for k in keys}}

class RecoveryQuorumTransparencyTests(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup); self.root=Path(self.temp.name)
  self.authorities={f"authority-{i}":Ed25519PrivateKey.generate() for i in range(4)}
  self.policy=policy(self.authorities,"recovery-transparent-v1")
  self.payload={"witness_id":"north","generation":9,"previous_state_sha256":"a"*64,"new_key_sha256":"b"*64}
  self.records=[]
  for index,aid in enumerate(("authority-0","authority-1","authority-2")):
   signer=RecoveryAuthoritySigner(aid,self.authorities[aid],str(self.root/(aid+".sqlite")))
   signer.approve(self.payload,self.policy); ledger=signer.export_approval_ledger()
   public=self.authorities[aid].public_key().public_bytes_raw().hex()
   checkpoint={"schema":CHECKPOINT_SCHEMA,"authority_id":aid,
    "authority_key_sha256":hashlib.sha256(bytes.fromhex(public)).hexdigest(),
    "sequence":1,"head_hash":ledger["head_sha256"]}
   keys={f"{aid}-anchor-{j}":Ed25519PrivateKey.generate() for j in range(4)}
   apolicy=anchor_policy(keys,aid+"-anchor-policy")
   witnesses={k:RecoveryAnchorWitness(k,v,str(self.root/(k+".sqlite"))) for k,v in keys.items()}
   anchor_payload=make_anchor_payload(checkpoint,1,"0"*64,apolicy)
   certificate=make_anchor_certificate(anchor_payload,apolicy,
    {k:witnesses[k] for k in sorted(witnesses)[:3]})
   evidence={"schema":"AML-SEF2-RECOVERY-EVIDENCE-BUNDLE-V1","authority_id":aid,
    "ledger":ledger,"checkpoint":checkpoint,"anchor_payload":anchor_payload,
    "anchor_certificate":certificate}
   self.records.append({"authority_id":aid,"authority_public_key_hex":public,
    "evidence":evidence,"anchor_policy":apolicy,"anchor_sequence":1,"previous_anchor_pin":"0"*64})
 def check(self,records=None,payload=None,policy_value=None):
  return verify_transparent_recovery_quorum(payload or self.payload,policy_value or self.policy,
   self.records if records is None else records)
 def test_three_independently_anchored_approvals_accept(self): self.assertTrue(self.check())
 def test_two_records_are_below_threshold(self): self.assertFalse(self.check(self.records[:2]))
 def test_duplicate_authority_rejected(self):
  records=copy.deepcopy(self.records); records[2]=copy.deepcopy(records[1])
  self.assertFalse(self.check(records))
 def test_wrong_authority_public_key_rejected(self):
  records=copy.deepcopy(self.records); records[0]["authority_public_key_hex"]=self.authorities["authority-3"].public_key().public_bytes_raw().hex()
  self.assertFalse(self.check(records))
 def test_payload_substitution_rejected(self):
  self.assertFalse(self.check(payload={**self.payload,"generation":10}))
 def test_stale_policy_substitution_rejected(self):
  p=copy.deepcopy(self.policy); p["policy_id"]="older-policy"
  self.assertFalse(self.check(policy_value=p))
 def test_authority_ledger_payload_mismatch_rejected(self):
  records=copy.deepcopy(self.records); records[0]["evidence"]["ledger"]["events"][-1]["payload_sha256"]="f"*64
  self.assertFalse(self.check(records))
 def test_authority_anchor_forgery_rejected(self):
  records=copy.deepcopy(self.records); records[0]["evidence"]["anchor_certificate"]["approvals"][0]["signature"]="00"*64
  self.assertFalse(self.check(records))
 def test_shared_anchor_key_between_authorities_rejected(self):
  records=copy.deepcopy(self.records)
  first_key=next(iter(records[0]["anchor_policy"]["authorities"].values()))
  first_name=next(iter(records[1]["anchor_policy"]["authorities"]))
  records[1]["anchor_policy"]["authorities"][first_name]=first_key
  self.assertFalse(self.check(records))
 def test_record_identity_must_match_embedded_evidence(self):
  records=copy.deepcopy(self.records); records[0]["evidence"]["authority_id"]="other"
  self.assertFalse(self.check(records))
