import copy,hashlib,json,tempfile,unittest
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from threshold_recovery import RecoveryAuthoritySigner,POLICY_SCHEMA
from recovery_anchor_quorum import (POLICY_SCHEMA as ANCHOR_SCHEMA,RecoveryAnchorWitness,
    make_anchor_payload,make_anchor_certificate)
from recovery_ledger_anchor import CHECKPOINT_SCHEMA
from recovery_evidence_reference_verifier import verify_recovery_evidence

class RecoveryEvidenceReferenceVerifierTests(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
  root=Path(self.temp.name)
  self.authority=Ed25519PrivateKey.generate()
  self.authority_id="recovery-authority-1"
  self.signer=RecoveryAuthoritySigner(self.authority_id,self.authority,str(root/"authority.sqlite"))
  recovery_keys={self.authority_id:self.authority}
  self.recovery_policy={"schema":POLICY_SCHEMA,"policy_id":"recovery-policy-v1",
   "threshold":1,"max_faults":0,"authorities":{self.authority_id:self.authority.public_key().public_bytes_raw().hex()}}
  self.signer.approve({"witness_id":"north","generation":1,"previous_state_sha256":"a"*64},self.recovery_policy)
  self.ledger=self.signer.export_approval_ledger()
  key_fp=hashlib.sha256(self.authority.public_key().public_bytes_raw()).hexdigest()
  self.checkpoint={"schema":CHECKPOINT_SCHEMA,"authority_id":self.authority_id,
   "authority_key_sha256":key_fp,"sequence":len(self.ledger["events"]),
   "head_hash":self.ledger["head_sha256"]}
  self.anchor_keys={f"anchor-{i}":Ed25519PrivateKey.generate() for i in range(4)}
  self.anchor_policy={"schema":ANCHOR_SCHEMA,"policy_id":"anchor-policy-v1","threshold":3,"max_faults":1,
   "authorities":{k:v.public_key().public_bytes_raw().hex() for k,v in self.anchor_keys.items()},
   "administrative_domains":{k:"operator-domain-"+k for k in self.anchor_keys}}
  self.anchor_witnesses={k:RecoveryAnchorWitness(k,v,str(root/(k+".sqlite"))) for k,v in self.anchor_keys.items()}
  self.payload=make_anchor_payload(self.checkpoint,1,"0"*64,self.anchor_policy)
  self.certificate=make_anchor_certificate(self.payload,self.anchor_policy,
   {k:self.anchor_witnesses[k] for k in ("anchor-0","anchor-1","anchor-2")})
  self.bundle={"schema":"AML-SEF2-RECOVERY-EVIDENCE-BUNDLE-V1","authority_id":self.authority_id,
   "ledger":self.ledger,"checkpoint":self.checkpoint,
   "anchor_payload":self.payload,"anchor_certificate":self.certificate}
  self.public=self.authority.public_key().public_bytes_raw().hex()
 def check(self,b=None,key=None,policy=None,seq=1,prev="0"*64):
  return verify_recovery_evidence(b or self.bundle,key or self.public,policy or self.anchor_policy,seq,prev)
 def test_complete_bundle_accepts(self): self.assertTrue(self.check())
 def test_ledger_truncation_rejected(self):
  b=copy.deepcopy(self.bundle); b["ledger"]["events"]=[]; b["ledger"]["head_sha256"]="0"*64
  self.assertFalse(self.check(b))
 def test_checkpoint_head_substitution_rejected(self):
  b=copy.deepcopy(self.bundle); b["checkpoint"]["head_hash"]="f"*64
  self.assertFalse(self.check(b))
 def test_authority_key_substitution_rejected(self):
  self.assertFalse(self.check(key=Ed25519PrivateKey.generate().public_key().public_bytes_raw().hex()))
 def test_authority_identity_substitution_rejected(self):
  b=copy.deepcopy(self.bundle); b["authority_id"]="other"
  self.assertFalse(self.check(b))
 def test_anchor_payload_checkpoint_substitution_rejected(self):
  b=copy.deepcopy(self.bundle); b["anchor_payload"]["checkpoint"]["head_hash"]="f"*64
  self.assertFalse(self.check(b))
 def test_anchor_certificate_forgery_rejected(self):
  b=copy.deepcopy(self.bundle); b["anchor_certificate"]["approvals"][0]["signature"]="00"*64
  self.assertFalse(self.check(b))
 def test_wrong_anchor_predecessor_pin_rejected(self): self.assertFalse(self.check(prev="f"*64))
 def test_wrong_anchor_sequence_rejected(self): self.assertFalse(self.check(seq=2))
 def test_anchor_policy_substitution_rejected(self):
  p=copy.deepcopy(self.anchor_policy)
  p["authorities"]["anchor-3"]=Ed25519PrivateKey.generate().public_key().public_bytes_raw().hex()
  self.assertFalse(self.check(policy=p))
 def test_below_threshold_anchor_certificate_rejected(self):
  b=copy.deepcopy(self.bundle); b["anchor_certificate"]["approvals"]=b["anchor_certificate"]["approvals"][:2]
  self.assertFalse(self.check(b))
 def test_mismatched_ledger_authority_rejected(self):
  b=copy.deepcopy(self.bundle); b["ledger"]["authority_id"]="other"
  self.assertFalse(self.check(b))
 def test_standalone_cli_accepts_complete_bundle(self):
  import subprocess,sys
  bundle=Path(self.temp.name)/"bundle.json"; policy=Path(self.temp.name)/"policy.json"
  bundle.write_text(json.dumps(self.bundle),encoding="utf-8"); policy.write_text(json.dumps(self.anchor_policy),encoding="utf-8")
  script=Path(__file__).with_name("recovery_evidence_reference_verifier.py")
  result=subprocess.run([sys.executable,str(script),str(bundle),"--authority-public-key",self.public,
    "--anchor-policy",str(policy),"--anchor-sequence","1","--previous-anchor-pin","0"*64],
    capture_output=True,text=True,check=False)
  self.assertEqual(result.returncode,0,result.stdout+result.stderr)
  self.assertIn("recovery ledger, checkpoint, authority key, and anchor quorum are linked",result.stdout)
