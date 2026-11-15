import copy,json,unittest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from recovery_anchor_quorum import (POLICY_SCHEMA,RecoveryAnchorWitness,make_anchor_payload,
    make_anchor_certificate)
from recovery_anchor_reference_verifier import verify_anchor_certificate,verify_json_bundle

class IndependentAnchorReferenceVerifierTests(unittest.TestCase):
 def setUp(self):
  import pathlib,tempfile
  from recovery_ledger_anchor import CHECKPOINT_SCHEMA
  self.temp=tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
  self.keys={f"anchor-{i}":Ed25519PrivateKey.generate() for i in range(4)}
  self.policy={"schema":POLICY_SCHEMA,"policy_id":"anchor-ref-v1","threshold":3,"max_faults":1,
   "authorities":{k:v.public_key().public_bytes_raw().hex() for k,v in self.keys.items()},
   "administrative_domains":{k:"operator-domain-"+k for k in self.keys}}
  self.witnesses={k:RecoveryAnchorWitness(k,v,str(pathlib.Path(self.temp.name)/(k+".sqlite"))) for k,v in self.keys.items()}
  self.checkpoint={"schema":CHECKPOINT_SCHEMA,"authority_id":"recovery-authority-1",
   "authority_key_sha256":"a"*64,"sequence":8,"head_hash":"b"*64}
  self.payload=make_anchor_payload(self.checkpoint,1,"0"*64,self.policy)
  self.certificate=make_anchor_certificate(self.payload,self.policy,
   {k:self.witnesses[k] for k in ("anchor-0","anchor-1","anchor-2")})
 def verify(self,p=None,c=None,policy=None,seq=1,previous="0"*64,target="recovery-authority-1",key="a"*64):
  return verify_anchor_certificate(p or self.payload,c or self.certificate,policy or self.policy,seq,previous,target,key)
 def test_reference_verifier_accepts_valid_three_of_four_certificate(self): self.assertTrue(self.verify())
 def test_reference_verifier_rejects_below_threshold(self):
  c=copy.deepcopy(self.certificate); c["approvals"]=c["approvals"][:2]; self.assertFalse(self.verify(c=c))
 def test_reference_verifier_rejects_duplicate_signer(self):
  c=copy.deepcopy(self.certificate); c["approvals"][1]=dict(c["approvals"][0]); c["approvals"].sort(key=lambda x:x["anchor_id"])
  self.assertFalse(self.verify(c=c))
 def test_reference_verifier_rejects_forged_signature(self):
  c=copy.deepcopy(self.certificate); c["approvals"][0]["signature"]="00"*64; self.assertFalse(self.verify(c=c))
 def test_reference_verifier_rejects_wrong_predecessor_pin(self): self.assertFalse(self.verify(previous="f"*64))
 def test_reference_verifier_rejects_wrong_sequence(self): self.assertFalse(self.verify(seq=2))
 def test_reference_verifier_rejects_wrong_target_identity(self): self.assertFalse(self.verify(target="other"))
 def test_reference_verifier_rejects_wrong_target_key(self): self.assertFalse(self.verify(key="f"*64))
 def test_reference_verifier_rejects_policy_substitution(self):
  p=copy.deepcopy(self.policy); p["authorities"]["anchor-3"]=Ed25519PrivateKey.generate().public_key().public_bytes_raw().hex()
  self.assertFalse(self.verify(policy=p))
 def test_reference_verifier_rejects_quorum_without_honest_intersection(self):
  p=copy.deepcopy(self.policy); p["threshold"]=2; self.assertFalse(self.verify(policy=p))
 def test_reference_verifier_rejects_duplicate_public_keys(self):
  p=copy.deepcopy(self.policy); p["authorities"]["anchor-3"]=p["authorities"]["anchor-0"]
  self.assertFalse(self.verify(policy=p))
 def test_reference_verifier_rejects_checkpoint_substitution(self):
  p=copy.deepcopy(self.payload); p["checkpoint"]["head_hash"]="c"*64; self.assertFalse(self.verify(p=p))
 def test_reference_verifier_rejects_noncanonical_hex(self):
  c=copy.deepcopy(self.certificate); c["approvals"][0]["signature"]="GG"*64; self.assertFalse(self.verify(c=c))
 def test_reference_json_parser_rejects_duplicate_keys(self):
  self.assertIsNone(verify_json_bundle('{"schema":"A","schema":"B"}'))
 def test_reference_json_parser_rejects_malformed_json(self): self.assertIsNone(verify_json_bundle("{"))

 def test_reference_verifier_rejects_duplicate_administrative_domains(self):
  p=copy.deepcopy(self.policy); p["administrative_domains"]["anchor-2"]=p["administrative_domains"]["anchor-0"]
  self.assertFalse(self.verify(policy=p))
