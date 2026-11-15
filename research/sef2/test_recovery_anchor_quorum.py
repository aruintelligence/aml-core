import copy,os,pathlib,tempfile,unittest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from recovery_anchor_quorum import (POLICY_SCHEMA,RecoveryAnchorWitness,
    make_anchor_payload,make_anchor_certificate,verify_anchor_certificate,validate_anchor_policy)
from recovery_ledger_anchor import CHECKPOINT_SCHEMA

def policy(keys,q=3,f=1):
 return {"schema":POLICY_SCHEMA,"policy_id":"independent-anchor-council-v1",
  "threshold":q,"max_faults":f,"authorities":{k:v.public_key().public_bytes_raw().hex() for k,v in keys.items()},
  "administrative_domains":{k:"operator-domain-"+k for k in keys}}

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
  self.assertFalse(verify_anchor_certificate(self.payload,self.certificate,p,1,"0"*64,"recovery-authority-1","a"*64))
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

 def test_quorum_anchor_detects_rollback_of_real_authority_approval_ledger(self):
  import shutil
  from threshold_recovery import RecoveryAuthoritySigner,POLICY_SCHEMA
  from recovery_ledger_anchor import event_chain_checkpoint,verify_event_chain,checkpoint_pin,CHECKPOINT_SCHEMA
  authority_keys={f"recovery-{i}":Ed25519PrivateKey.generate() for i in range(4)}
  authority_policy={"schema":POLICY_SCHEMA,"policy_id":"recovery-ledger-council",
   "threshold":3,"max_faults":1,
   "authorities":{k:v.public_key().public_bytes_raw().hex() for k,v in authority_keys.items()}}
  ledger=str(pathlib.Path(self.temp.name)/"recovery-authority.sqlite")
  signer=RecoveryAuthoritySigner("recovery-0",authority_keys["recovery-0"],ledger)
  signer.approve({"witness_id":"north","generation":1,"previous_state_sha256":"a"*64,"new_key":"b"*64},authority_policy)
  snapshot=str(pathlib.Path(self.temp.name)/"pre-anchor-snapshot.sqlite")
  shutil.copy2(ledger,snapshot)
  signer.approve({"witness_id":"north","generation":2,"previous_state_sha256":"c"*64,"new_key":"d"*64},authority_policy)
  event_checkpoint=event_chain_checkpoint(ledger,"recovery-0",authority_keys["recovery-0"].public_key().public_bytes_raw().hex())
  event_pin=checkpoint_pin(event_checkpoint)
  checkpoint={"schema":CHECKPOINT_SCHEMA,"authority_id":event_checkpoint["authority_id"],
   "authority_key_sha256":event_checkpoint["authority_key_sha256"],
   "sequence":event_checkpoint["sequence"],"head_hash":event_checkpoint["head_hash"]}
  pin=checkpoint_pin(checkpoint)
  anchor_keys={f"ledger-anchor-{i}":Ed25519PrivateKey.generate() for i in range(4)}
  anchor_policy=policy(anchor_keys)
  anchor_witnesses={k:RecoveryAnchorWitness(k,v,str(pathlib.Path(self.temp.name)/(k+".sqlite"))) for k,v in anchor_keys.items()}
  payload=make_anchor_payload(checkpoint,1,"0"*64,anchor_policy)
  certificate=make_anchor_certificate(payload,anchor_policy,
   {k:anchor_witnesses[k] for k in ("ledger-anchor-0","ledger-anchor-1","ledger-anchor-2")})
  self.assertTrue(verify_anchor_certificate(payload,certificate,anchor_policy,1,"0"*64,
   "recovery-0",checkpoint["authority_key_sha256"]))
  self.assertTrue(verify_event_chain(ledger,authority_keys["recovery-0"].public_key().public_bytes_raw().hex(),event_checkpoint,event_pin))
  shutil.copy2(snapshot,ledger)
  self.assertFalse(verify_event_chain(ledger,authority_keys["recovery-0"].public_key().public_bytes_raw().hex(),checkpoint,pin))
  self.assertTrue(verify_anchor_certificate(payload,certificate,anchor_policy,1,"0"*64,
   "recovery-0",checkpoint["authority_key_sha256"]))

 def test_certificate_succeeds_when_extra_witness_is_stale_after_quorum(self):
  stale=make_anchor_payload({**self.checkpoint,"head_hash":"c"*64},1,"0"*64,self.policy)
  self.witnesses["anchor-3"].approve(stale,self.policy)
  certificate=make_anchor_certificate(self.payload,self.policy,self.witnesses)
  self.assertEqual(len(certificate["approvals"]),3)
  self.assertTrue(verify_anchor_certificate(self.payload,certificate,self.policy,
   1,"0"*64,"recovery-authority-1","a"*64))
 def test_certificate_fails_when_fewer_than_threshold_witnesses_can_vote(self):
  stale=make_anchor_payload({**self.checkpoint,"head_hash":"c"*64},1,"0"*64,self.policy)
  unavailable={}
  for aid,key in self.keys.items():
   path=str(pathlib.Path(self.temp.name)/(aid+"-unavailable.sqlite"))
   unavailable[aid]=RecoveryAnchorWitness(aid,key,path)
  for aid in ("anchor-0","anchor-1"):
   unavailable[aid].approve(stale,self.policy)
  with self.assertRaisesRegex(ValueError,"insufficient valid anchor approvals"):
   make_anchor_certificate(self.payload,self.policy,unavailable)

 def test_independent_checkpoint_verifier_rejects_cross_policy_same_generation_equivocation(self):
  import hashlib,sqlite3
  from signed_receipt import canonical
  from threshold_recovery import DOMAIN,RecoveryAuthoritySigner
  from recovery_ledger_anchor import event_chain_checkpoint,verify_event_chain,checkpoint_pin
  key=Ed25519PrivateKey.generate()
  authority_id="authority-cross-policy"
  path=str(pathlib.Path(self.temp.name)/"cross-policy.sqlite")
  signer=RecoveryAuthoritySigner(authority_id,key,path)
  policy={"schema":"AML-SEF2-RECOVERY-QUORUM-POLICY-V1","policy_id":"policy-old",
   "threshold":3,"max_faults":1,"authorities":{authority_id:key.public_key().public_bytes_raw().hex(),
    "a1":Ed25519PrivateKey.generate().public_key().public_bytes_raw().hex(),
    "a2":Ed25519PrivateKey.generate().public_key().public_bytes_raw().hex(),
    "a3":Ed25519PrivateKey.generate().public_key().public_bytes_raw().hex()}}
  signer.approve({"witness_id":"north","generation":4,"previous_state_sha256":"a"*64,"new_key":"b"*64},policy)
  with sqlite3.connect(path) as con:
   previous=con.execute("SELECT event_sha256 FROM recovery_approval_events ORDER BY sequence DESC").fetchone()[0]
   policy_id="policy-new"; pd=hashlib.sha256(policy_id.encode()).hexdigest()
   digest=hashlib.sha256(b"second signed payload").hexdigest()
   signature=key.sign(DOMAIN+canonical({"policy_sha256":pd,"payload_sha256":digest})).hex()
   event={"sequence":2,"previous_event_sha256":previous,"policy_id":policy_id,
    "authority_id":authority_id,"witness_id":"north","generation":4,
    "policy_sha256":pd,"previous_state_sha256":"c"*64,"payload_sha256":digest,"signature":signature}
   event_hash=hashlib.sha256(canonical(event)).hexdigest()
   con.execute("INSERT INTO recovery_approval_events VALUES (?,?,?,?,?,?,?,?,?,?,?)",
    (2,previous,policy_id,authority_id,"north",4,pd,"c"*64,digest,signature,event_hash))
  public=key.public_key().public_bytes_raw().hex()
  checkpoint=event_chain_checkpoint(path,authority_id,public)
  self.assertFalse(verify_event_chain(path,public,checkpoint,checkpoint_pin(checkpoint)))

 def test_anchor_database_cannot_be_reused_under_different_identity(self):
  path=str(pathlib.Path(self.temp.name)/"anchor-0.sqlite")
  with self.assertRaisesRegex(ValueError,"another anchor identity"):
   RecoveryAnchorWitness("anchor-1",self.keys["anchor-1"],path)
 def test_anchor_database_cannot_be_reused_under_replacement_key(self):
  path=str(pathlib.Path(self.temp.name)/"anchor-0.sqlite")
  with self.assertRaisesRegex(ValueError,"another anchor identity"):
   RecoveryAnchorWitness("anchor-0",Ed25519PrivateKey.generate(),path)

 def test_policy_rejects_two_anchor_keys_in_one_administrative_domain(self):
  p=copy.deepcopy(self.policy); p["administrative_domains"]["anchor-1"]=p["administrative_domains"]["anchor-0"]
  self.assertFalse(validate_anchor_policy(p))
 def test_policy_requires_complete_administrative_domain_map(self):
  p=copy.deepcopy(self.policy); del p["administrative_domains"]["anchor-3"]
  self.assertFalse(validate_anchor_policy(p))
