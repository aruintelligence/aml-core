import copy,hashlib,json,tempfile,unittest
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from threshold_recovery import RecoveryAuthoritySigner,POLICY_SCHEMA
from recovery_anchor_quorum import POLICY_SCHEMA as ANCHOR_SCHEMA,RecoveryAnchorWitness,make_anchor_payload,make_anchor_certificate
from recovery_ledger_anchor import CHECKPOINT_SCHEMA
from recovery_evidence_bundle import build_recovery_evidence,write_recovery_evidence
from recovery_evidence_reference_verifier import verify_recovery_evidence
class RecoveryEvidenceBundleTests(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup); root=Path(self.temp.name)
  self.key=Ed25519PrivateKey.generate(); self.public=self.key.public_key().public_bytes_raw().hex()
  self.authority_id="authority-bundle"; self.signer=RecoveryAuthoritySigner(self.authority_id,self.key,str(root/"ledger.sqlite"))
  policy={"schema":POLICY_SCHEMA,"policy_id":"p","threshold":1,"max_faults":0,"authorities":{self.authority_id:self.public}}
  self.signer.approve({"witness_id":"north","generation":1,"previous_state_sha256":"a"*64},policy)
  self.ledger=self.signer.export_approval_ledger()
  fp=hashlib.sha256(bytes.fromhex(self.public)).hexdigest()
  self.checkpoint={"schema":CHECKPOINT_SCHEMA,"authority_id":self.authority_id,"authority_key_sha256":fp,
   "sequence":1,"head_hash":self.ledger["head_sha256"]}
  self.anchor_keys={f"a{i}":Ed25519PrivateKey.generate() for i in range(4)}
  self.anchor_policy={"schema":ANCHOR_SCHEMA,"policy_id":"anchors","threshold":3,"max_faults":1,
   "authorities":{k:v.public_key().public_bytes_raw().hex() for k,v in self.anchor_keys.items()},
   "administrative_domains":{k:"operator-domain-"+k for k in self.anchor_keys}}
  self.anchor_witnesses={k:RecoveryAnchorWitness(k,v,str(root/(k+".sqlite"))) for k,v in self.anchor_keys.items()}
  self.payload=make_anchor_payload(self.checkpoint,1,"0"*64,self.anchor_policy)
  self.cert=make_anchor_certificate(self.payload,self.anchor_policy,{k:self.anchor_witnesses[k] for k in ("a0","a1","a2")})
 def build(self,ledger=None):
  return build_recovery_evidence(self.authority_id,ledger or self.ledger,self.checkpoint,self.payload,self.cert,
   self.public,self.anchor_policy,1,"0"*64)
 def test_deterministic_canonical_package(self):
  first=self.build(); second=self.build()
  self.assertEqual(first["canonical_json"],second["canonical_json"]); self.assertEqual(first["sha256"],second["sha256"])
  self.assertEqual(first["sha256"],hashlib.sha256(first["canonical_json"].encode()).hexdigest())
 def test_independent_verifier_accepts_produced_bundle(self):
  p=self.build()
  self.assertTrue(verify_recovery_evidence(p["bundle"],self.public,self.anchor_policy,1,"0"*64))
 def test_producer_refuses_truncated_ledger(self):
  ledger=copy.deepcopy(self.ledger); ledger["events"]=[]; ledger["head_sha256"]="0"*64
  with self.assertRaises(ValueError): self.build(ledger)
 def test_create_only_file_prevents_silent_overwrite(self):
  path=Path(self.temp.name)/"evidence.json"
  digest=write_recovery_evidence(path,self.authority_id,self.ledger,self.checkpoint,self.payload,self.cert,
   self.public,self.anchor_policy,1,"0"*64)
  self.assertEqual(digest,hashlib.sha256(path.read_bytes()).hexdigest())
  with self.assertRaises(FileExistsError):
   write_recovery_evidence(path,self.authority_id,self.ledger,self.checkpoint,self.payload,self.cert,
    self.public,self.anchor_policy,1,"0"*64)
 def test_transport_roundtrip_preserves_verifiability(self):
  p=self.build(); restored=json.loads(p["canonical_json"])
  self.assertTrue(verify_recovery_evidence(restored,self.public,self.anchor_policy,1,"0"*64))
