import copy,os,pathlib,tempfile,unittest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from recovery_anchor_quorum import (POLICY_SCHEMA,RecoveryAnchorWitness,
    make_anchor_payload,make_anchor_certificate,verify_anchor_certificate,validate_anchor_policy)
from recovery_ledger_anchor import CHECKPOINT_SCHEMA

def policy(keys,q=3,f=1):
 return {"schema":POLICY_SCHEMA,"policy_id":"independent-anchor-council-v1",
  "threshold":q,"max_faults":f,"authorities":{k:v.public_key().public_bytes_raw().hex() for k,v in keys.items()}}

class RecoveryAnchorQuorumTests(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
  self.keys={f"anchor-{i}":Ed25519PrivateKey.generate() for i in range(4)}
  self.policy=policy(self.keys)
  self.witnesses={k:RecoveryAnchorWitness(k,v,str(pathlib.Path(self.temp.name)/(k+".sqlite"))) for k,v in self.keys.items()}
  self.checkpoint={"schema":CHECKPOINT_SCHEMA,"authority_id":"recovery-authority-1",
   "authority_key_sha256":"a"*64,"sequence":3,"head_hash":"b"*64}
  self.payload=make_anchor_payload(self.checkpoint,1,"0"*64,self.policy)
  self.certificate=make_anchor_certificate(self.payload,self.policy,
   {k:self.witnesses[k] for k in ("anchor-0","anchor-1","anchor-2")})
 def test_three_of_four_independent_anchor_votes_verify(self):
  self.assertTrue(verify_anchor_certificate(self.payload,self.certificate,self.policy,1,"0"*64,"recovery-authority-1","a"*64))
 def test_two_votes_are_insufficient(self):
  c=copy.deepcopy(self.certificate); c["approvals"]=c["approvals"][:2]
  self.assertFalse(verify_anchor_certificate(self.payload,c,self.policy,1,"0"*64,"recovery-authority-1","a"*64))
 def test_duplicate_anchor_identity_rejected(self):
  c=copy.deepcopy(self.certificate); c["approvals"][1]=dict(c["approvals"][0])
  c["approvals"].sort(key=lambda x:x["anchor_id"])
  self.assertFalse(verify_anchor_certificate(self.payload,c,self.policy,1,"0"*64,"recovery-authority-1","a"*64))
 def test_forged_anchor_signature_rejected(self):
  c=copy.deepcopy(self.certificate); c["approvals"][0]["signature"]="00"*64
  self.assertFalse(verify_anchor_certificate(self.payload,c,self.policy,1,"0"*64,"recovery-authority-1","a"*64))
 def test_checkpoint_substitution_rejected(self):
  p=copy.deepcopy(self.payload); p["checkpoint"]["head_hash"]="c"*64
  self.assertFalse(verify_anchor_certificate(p,self.certificate,self.policy,1,"0"*64,"recovery-authority-1","a"*64))
 def test_policy_substitution_rejected(self):
  p=copy.deepcopy(self.policy); p["threshold"]=2
  self.assertFalse(verify_anchor_certificate(self.payload,self.certificate,p,1,"0"*64))
 def test_stale_expected_pin_rejected(self):
  self.assertFalse(verify_anchor_certificate(self.payload,self.certificate,self.policy,1,"f"*64,"recovery-authority-1","a"*64))
 def test_stale_sequence_rejected(self):
  self.assertFalse(verify_anchor_certificate(self.payload,self.certificate,self.policy,2,"0"*64,"recovery-authority-1","a"*64))
 def test_witness_refuses_conflicting_checkpoint_at_same_sequence(self):
  changed=make_anchor_payload({**self.checkpoint,"head_hash":"c"*64},1,"0"*64,self.policy)
  with self.assertRaisesRegex(ValueError,"equivocation"):
   self.witnesses["anchor-0"].approve(changed,self.policy)
 def test_witness_refuses_wrong_previous_pin_and_sequence(self):
  changed={**self.payload,"sequence":2}
  with self.assertRaisesRegex(ValueError,"stale or forked"):
   self.witnesses["anchor-3"].approve(changed,self.policy)
 def test_witness_persists_successor_state_across_restart(self):
  changed=make_anchor_payload({**self.checkpoint,"sequence":4,"head_hash":"c"*64},
   2,self.payload["checkpoint_pin_sha256"],self.policy)
  self.witnesses["anchor-0"].approve(changed,self.policy)
  restarted=RecoveryAnchorWitness("anchor-0",self.keys["anchor-0"],
   str(pathlib.Path(self.temp.name)/"anchor-0.sqlite"))
  conflicting=make_anchor_payload({**self.checkpoint,"sequence":5,"head_hash":"d"*64},
   3,"f"*64,self.policy)
  with self.assertRaisesRegex(ValueError,"stale or forked"):
   restarted.approve(conflicting,self.policy)
 def test_exact_retry_is_idempotent(self):
  first=self.witnesses["anchor-0"].approve(self.payload,self.policy)
  second=self.witnesses["anchor-0"].approve(self.payload,self.policy)
  self.assertEqual(first,second)
 def test_anchor_witness_rejects_boolean_sequence(self):
  malformed={**self.payload,"sequence":True}
  with self.assertRaisesRegex(ValueError,"invalid anchor payload"):
   self.witnesses["anchor-3"].approve(malformed,self.policy)
 def test_anchor_witness_rejects_malformed_checkpoint_hash(self):
  malformed=copy.deepcopy(self.payload)
  malformed["checkpoint"]["head_hash"]="not-a-hash"
  with self.assertRaisesRegex(ValueError,"invalid anchor payload"):
   self.witnesses["anchor-3"].approve(malformed,self.policy)
 def test_wrong_target_authority_identity_rejected(self):
  self.assertFalse(verify_anchor_certificate(self.payload,self.certificate,self.policy,
   1,"0"*64,"different-authority","a"*64))
 def test_wrong_target_authority_key_fingerprint_rejected(self):
  self.assertFalse(verify_anchor_certificate(self.payload,self.certificate,self.policy,
   1,"0"*64,"recovery-authority-1","f"*64))
 def test_policy_requires_byzantine_safe_quorum(self):
  bad=copy.deepcopy(self.policy); bad["threshold"]=2
  self.assertFalse(validate_anchor_policy(bad))
 def test_policy_rejects_fault_bound_inconsistent_with_council_size(self):
  bad=copy.deepcopy(self.policy); bad["max_faults"]=2
  self.assertFalse(validate_anchor_policy(bad))
 def test_anchor_witness_rejects_insecure_database_permissions(self):
  path=str(pathlib.Path(self.temp.name)/"insecure.sqlite")
  pathlib.Path(path).write_bytes(b""); os.chmod(path,0o644)
  with self.assertRaisesRegex(ValueError,"private regular file"):
   RecoveryAnchorWitness("anchor-0",self.keys["anchor-0"],path)
