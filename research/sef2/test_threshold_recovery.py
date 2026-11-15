import copy,unittest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from threshold_recovery import DOMAIN,POLICY_SCHEMA,make_approval_bundle,make_threshold_transition,RecoveryAuthoritySigner,policy_digest,payload_digest,validate_policy,verify_approval_bundle
def make_policy(keys,threshold=3):
 return {"schema":POLICY_SCHEMA,"policy_id":"recovery-council-1","threshold":threshold,"max_faults":1,"authorities":{n:k.public_key().public_bytes_raw().hex() for n,k in keys.items()}}
class ThresholdRecoveryTests(unittest.TestCase):
 def setUp(self):
  self.keys={f"authority-{i}":Ed25519PrivateKey.generate() for i in range(4)}
  self.policy=make_policy(self.keys,3); self.payload={"witness_id":"north","generation":7,"new_key":"a"*64}
  self.bundle=make_approval_bundle(self.payload,self.policy,{k:self.keys[k] for k in ("authority-0","authority-1","authority-2")})
 def test_three_of_four_approvals_succeed(self): self.assertTrue(verify_approval_bundle(self.payload,self.bundle,self.policy))
 def test_two_of_four_is_insufficient(self):
  b=copy.deepcopy(self.bundle)
  b["approvals"]=b["approvals"][:2]
  self.assertFalse(verify_approval_bundle(self.payload,b,self.policy))
 def test_one_signer_cannot_be_counted_twice(self):
  b=copy.deepcopy(self.bundle); b["approvals"][1]=dict(b["approvals"][0]); b["approvals"].sort(key=lambda x:x["authority_id"])
  self.assertFalse(verify_approval_bundle(self.payload,b,self.policy))
 def test_unknown_authority_rejected(self):
  b=copy.deepcopy(self.bundle); b["approvals"][0]["authority_id"]="unknown"; self.assertFalse(verify_approval_bundle(self.payload,b,self.policy))
 def test_signature_tampering_rejected(self):
  b=copy.deepcopy(self.bundle); b["approvals"][0]["signature"]="00"*64; self.assertFalse(verify_approval_bundle(self.payload,b,self.policy))
 def test_payload_substitution_rejected(self): self.assertFalse(verify_approval_bundle({**self.payload,"generation":8},self.bundle,self.policy))
 def test_policy_substitution_rejected(self):
  p=copy.deepcopy(self.policy); p["threshold"]=2; self.assertFalse(verify_approval_bundle(self.payload,self.bundle,p))
 def test_key_identity_substitution_rejected(self):
  p=copy.deepcopy(self.policy); p["authorities"]["authority-0"]=Ed25519PrivateKey.generate().public_key().public_bytes_raw().hex()
  self.assertFalse(verify_approval_bundle(self.payload,self.bundle,p))
 def test_duplicate_public_keys_make_policy_invalid(self):
  p=copy.deepcopy(self.policy); p["authorities"]["authority-3"]=p["authorities"]["authority-0"]; self.assertFalse(validate_policy(p))
 def test_invalid_threshold_rejected(self):
  for q in (0,2,5,True,2.5):
   p=copy.deepcopy(self.policy); p["threshold"]=q; self.assertFalse(validate_policy(p))
 def test_policy_rejects_quorum_without_honest_intersection(self):
  p=copy.deepcopy(self.policy); p["threshold"]=2
  self.assertFalse(validate_policy(p))
 def test_policy_rejects_unavailable_quorum(self):
  p=copy.deepcopy(self.policy); p["threshold"]=4
  self.assertFalse(validate_policy(p))
 def test_policy_rejects_fault_bound_above_classical_bft_limit(self):
  p=copy.deepcopy(self.policy); p["max_faults"]=2
  self.assertFalse(validate_policy(p))
 def test_quorum_intersection_contains_honest_authority(self):
  import itertools
  n=len(self.policy["authorities"]); q=self.policy["threshold"]; f=self.policy["max_faults"]
  members=set(self.policy["authorities"])
  quorums=list(itertools.combinations(members,q))
  for left,right in itertools.combinations(quorums,2):
   self.assertGreater(len(set(left)&set(right)),f)
 def test_unsorted_approvals_rejected(self):
  b=copy.deepcopy(self.bundle); b["approvals"].reverse(); self.assertFalse(verify_approval_bundle(self.payload,b,self.policy))
 def test_signer_key_mismatch_rejected_when_building(self):
  with self.assertRaises(ValueError): make_approval_bundle(self.payload,self.policy,{"authority-0":Ed25519PrivateKey.generate(),"authority-1":self.keys["authority-1"],"authority-2":self.keys["authority-2"]})
 def test_nonmember_signer_rejected_when_building(self):
  with self.assertRaises(ValueError): make_approval_bundle(self.payload,self.policy,{"outsider":Ed25519PrivateKey.generate()})
 def test_malformed_bundle_fails_closed(self): self.assertFalse(verify_approval_bundle(self.payload,{"approvals":[]},self.policy))
 def test_invalid_policy_fails_closed(self): self.assertFalse(verify_approval_bundle(self.payload,self.bundle,{"schema":"wrong"}))

class ThresholdRecoveryEnrollmentTests(unittest.TestCase):
 def setUp(self):
  import pathlib,tempfile
  from trust_enrollment import Enrollment,propose
  from witness_recovery_enrollment import WitnessRecoveryEnrollment
  from threshold_recovery import ThresholdRecoveryPublicKey
  self.temp=tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
  self.trust_path=str(pathlib.Path(self.temp.name)/"trust.sqlite")
  self.recovery_path=str(pathlib.Path(self.temp.name)/"recovery.sqlite")
  self.approver=Ed25519PrivateKey.generate(); self.old=Ed25519PrivateKey.generate(); self.new=Ed25519PrivateKey.generate()
  self.keys={"authority":self.approver.public_key().public_bytes_raw().hex(),
    "provider":Ed25519PrivateKey.generate().public_key().public_bytes_raw().hex(),
    "witness":self.old.public_key().public_bytes_raw().hex()}
  self.enrollment=Enrollment(self.trust_path,self.approver.public_key())
  self.enrollment.accept(propose(self.approver,1,self.keys))
  self.authorities={f"council-{i}":Ed25519PrivateKey.generate() for i in range(4)}
  self.policy=make_policy(self.authorities,3)
  self.verifier=ThresholdRecoveryPublicKey(self.policy)
  self.coordinator=WitnessRecoveryEnrollment(self.trust_path,self.recovery_path,self.verifier,self.policy["policy_id"])
  self.checkpoint={"schema":"AML-SEF2-SIGNED-HISTORY-CHECKPOINT-V1","epoch":1,"head_hash":"a"*64,"count":1,"approver_key_id":"c"*64}
  self.state=self.coordinator.initialize("north",self.checkpoint)
  self.next_checkpoint={**self.checkpoint,"epoch":2,"head_hash":"b"*64,"count":2}
  self.authority_signers={}
  for aid,key in self.authorities.items():
   self.authority_signers[aid]=RecoveryAuthoritySigner(aid,key,str(pathlib.Path(self.temp.name)/(aid+".sqlite")))
  self.transition=make_threshold_transition(self.new,"north",self.state,self.next_checkpoint,
    self.policy,{k:self.authority_signers[k] for k in ("council-0","council-1","council-2")})
 def test_threshold_recovery_replaces_and_revokes_old_witness_key(self):
  from witness_recovery_enrollment import WitnessRecoveryEnrollment
  self.assertEqual(self.coordinator.recover("north",self.transition),"RECOVERED")
  manifest=self.enrollment.manifest()
  self.assertEqual(manifest["public_keys"]["witness"],self.new.public_key().public_bytes_raw().hex())
  self.assertIn(self.old.public_key().public_bytes_raw().hex(),manifest["revoked_key_hex"])
 def test_two_approvals_cannot_recover(self):
  import json
  from signed_receipt import canonical
  bad=dict(self.transition)
  bundle=json.loads(bytes.fromhex(bad["recovery_signature"]))
  bundle["approvals"]=bundle["approvals"][:2]
  bad["recovery_signature"]=canonical(bundle).hex()
  self.assertEqual(self.coordinator.recover("north",bad),"INVALID_RECOVERY")
 def test_wrong_pinned_policy_cannot_recover(self):
  other=make_policy({f"other-{i}":Ed25519PrivateKey.generate() for i in range(4)},3)
  from threshold_recovery import ThresholdRecoveryPublicKey
  from witness_recovery_enrollment import WitnessRecoveryEnrollment
  coordinator=WitnessRecoveryEnrollment(self.trust_path,self.recovery_path,ThresholdRecoveryPublicKey(other),other["policy_id"])
  self.assertEqual(coordinator.recover("north",self.transition),"INVALID_RECOVERY")
 def test_threshold_transition_replay_rejected(self):
  self.assertEqual(self.coordinator.recover("north",self.transition),"RECOVERED")
  self.assertEqual(self.coordinator.recover("north",self.transition),"INVALID_RECOVERY")


 def test_transition_builder_rejects_ephemeral_raw_private_keys(self):
  with self.assertRaisesRegex(ValueError,"durable RecoveryAuthoritySigner"):
   make_threshold_transition(self.new,"north",self.state,self.next_checkpoint,self.policy,
    {k:self.authorities[k] for k in ("council-0","council-1","council-2")})

class RecoveryAuthorityLedgerTests(unittest.TestCase):
 def setUp(self):
  import tempfile,pathlib
  self.temp=tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
  self.ledger=str(pathlib.Path(self.temp.name)/"authority.sqlite")
  self.key=Ed25519PrivateKey.generate()
  self.policy=make_policy({"authority-0":self.key,"authority-1":Ed25519PrivateKey.generate(),
    "authority-2":Ed25519PrivateKey.generate(),"authority-3":Ed25519PrivateKey.generate()},3)
  self.signer=RecoveryAuthoritySigner("authority-0",self.key,self.ledger)
  self.payload={"witness_id":"north","generation":1,"previous_state_sha256":"a"*64,"new_key":"b"*64}
 def test_legacy_ledger_migrates_without_dropping_existing_approval(self):
  import sqlite3,pathlib
  from signed_receipt import canonical
  from threshold_recovery import RecoveryAuthoritySigner,verify_approval_ledger
  path=str(pathlib.Path(self.temp.name)/"legacy.sqlite")
  with sqlite3.connect(path) as con:
   con.execute("""CREATE TABLE recovery_approval_ledger_v3 (
    policy_id TEXT NOT NULL,authority_id TEXT NOT NULL,witness_id TEXT NOT NULL,
    generation INTEGER NOT NULL,policy_sha256 TEXT NOT NULL,previous_state_sha256 TEXT NOT NULL,
    payload_sha256 TEXT NOT NULL,signature TEXT NOT NULL,
    PRIMARY KEY(policy_id,authority_id,witness_id,generation))""")
   pd=policy_digest(self.policy); digest=payload_digest(self.payload)
   sig=self.key.sign(DOMAIN+canonical({"policy_sha256":pd,"payload_sha256":digest})).hex()
   con.execute("INSERT INTO recovery_approval_ledger_v3 VALUES (?,?,?,?,?,?,?,?)",
    (self.policy["policy_id"],"authority-0","north",1,pd,"a"*64,digest,sig))
  import os
  os.chmod(path,0o600)
  signer=RecoveryAuthoritySigner("authority-0",self.key,path)
  ledger=signer.export_approval_ledger()
  self.assertEqual(len(ledger["events"]),1)
  self.assertTrue(verify_approval_ledger(ledger,self.key.public_key(),ledger["head_sha256"]))
  with sqlite3.connect(path) as con:
   self.assertEqual(con.execute("SELECT COUNT(*) FROM recovery_approval_ledger_v4").fetchone()[0],1)
 def test_legacy_migration_rejects_approval_signed_by_another_key(self):
  import sqlite3,pathlib,os
  from signed_receipt import canonical
  from threshold_recovery import RecoveryAuthoritySigner
  path=str(pathlib.Path(self.temp.name)/"wrong-key-legacy.sqlite")
  with sqlite3.connect(path) as con:
   con.execute("""CREATE TABLE recovery_approval_ledger_v3 (
    policy_id TEXT NOT NULL,authority_id TEXT NOT NULL,witness_id TEXT NOT NULL,
    generation INTEGER NOT NULL,policy_sha256 TEXT NOT NULL,previous_state_sha256 TEXT NOT NULL,
    payload_sha256 TEXT NOT NULL,signature TEXT NOT NULL,
    PRIMARY KEY(policy_id,authority_id,witness_id,generation))""")
   pd=policy_digest(self.policy); digest=payload_digest(self.payload)
   wrong=Ed25519PrivateKey.generate()
   sig=wrong.sign(DOMAIN+canonical({"policy_sha256":pd,"payload_sha256":digest})).hex()
   con.execute("INSERT INTO recovery_approval_ledger_v3 VALUES (?,?,?,?,?,?,?,?)",
    (self.policy["policy_id"],"authority-0","north",1,pd,"a"*64,digest,sig))
  os.chmod(path,0o600)
  with self.assertRaisesRegex(ValueError,"does not match pinned authority key"):
   RecoveryAuthoritySigner("authority-0",self.key,path)

 def test_legacy_migration_fails_closed_on_conflicting_policy_rows(self):
  import sqlite3,pathlib
  from signed_receipt import canonical
  from threshold_recovery import RecoveryAuthoritySigner
  path=str(pathlib.Path(self.temp.name)/"conflicting-legacy.sqlite")
  with sqlite3.connect(path) as con:
   con.execute("""CREATE TABLE recovery_approval_ledger_v3 (
    policy_id TEXT NOT NULL,authority_id TEXT NOT NULL,witness_id TEXT NOT NULL,
    generation INTEGER NOT NULL,policy_sha256 TEXT NOT NULL,previous_state_sha256 TEXT NOT NULL,
    payload_sha256 TEXT NOT NULL,signature TEXT NOT NULL,
    PRIMARY KEY(policy_id,authority_id,witness_id,generation))""")
   for policy_id,keychar in (("policy-old","b"),("policy-new","c")):
    payload={**self.payload,"new_key":keychar*64}
    pd=policy_digest({**self.policy,"policy_id":policy_id}); digest=payload_digest(payload)
    sig=self.key.sign(DOMAIN+canonical({"policy_sha256":pd,"payload_sha256":digest})).hex()
    con.execute("INSERT INTO recovery_approval_ledger_v3 VALUES (?,?,?,?,?,?,?,?)",
     (policy_id,"authority-0","north",1,pd,"a"*64,digest,sig))
  import os
  os.chmod(path,0o600)
  with self.assertRaisesRegex(ValueError,"conflicting approvals"):
   RecoveryAuthoritySigner("authority-0",self.key,path)

 def test_authority_refuses_conflicting_payload_for_same_recovery_generation(self):
  self.signer.approve(self.payload,self.policy)
  changed={**self.payload,"new_key":"c"*64}
  with self.assertRaisesRegex(ValueError,"equivocation"):
   self.signer.approve(changed,self.policy)
 def test_exact_approval_is_idempotent(self):
  first=self.signer.approve(self.payload,self.policy)
  second=self.signer.approve(self.payload,self.policy)
  self.assertEqual(first,second)
 def test_concurrent_conflicting_approvals_only_one_is_accepted(self):
  import concurrent.futures
  left={**self.payload,"new_key":"d"*64}; right={**self.payload,"new_key":"e"*64}
  def attempt(payload):
   try: return ("ok",self.signer.approve(payload,self.policy))
   except ValueError: return ("rejected",None)
  with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
   results=list(pool.map(attempt,(left,right)))
  self.assertEqual([x[0] for x in results].count("ok"),1)
  self.assertEqual([x[0] for x in results].count("rejected"),1)
 def test_signer_ledger_can_produce_threshold_approval_bundle(self):
  signers={"authority-0":self.signer}
  for i in (1,2):
   key=Ed25519PrivateKey.generate()
   signers[f"authority-{i}"]=key
   self.policy["authorities"][f"authority-{i}"]=key.public_key().public_bytes_raw().hex()
  self.assertTrue(verify_approval_bundle(self.payload,make_approval_bundle(self.payload,self.policy,signers),self.policy))

 def test_conflicting_predecessor_state_at_same_generation_is_refused(self):
  self.signer.approve(self.payload,self.policy)
  changed={**self.payload,"previous_state_sha256":"f"*64}
  with self.assertRaisesRegex(ValueError,"equivocation"):
   self.signer.approve(changed,self.policy)

 def test_authority_refuses_same_generation_with_different_parent(self):
  self.signer.approve(self.payload,self.policy)
  changed={**self.payload,"previous_state_sha256":"c"*64}
  with self.assertRaisesRegex(ValueError,"equivocation"):
   self.signer.approve(changed,self.policy)
 def test_authority_refuses_same_generation_after_policy_revision(self):
  self.signer.approve(self.payload,self.policy)
  revised=copy.deepcopy(self.policy)
  revised["authorities"]["authority-3"]=Ed25519PrivateKey.generate().public_key().public_bytes_raw().hex()
  with self.assertRaisesRegex(ValueError,"equivocation"):
   self.signer.approve(self.payload,revised)

 def test_authority_refuses_same_generation_after_policy_id_rotation(self):
  self.signer.approve(self.payload,self.policy)
  rotated=copy.deepcopy(self.policy)
  rotated["policy_id"]="recovery-council-2"
  with self.assertRaisesRegex(ValueError,"equivocation"):
   self.signer.approve(self.payload,rotated)

 def test_equivocation_record_survives_signer_restart(self):
  self.signer.approve(self.payload,self.policy)
  restarted=RecoveryAuthoritySigner("authority-0",self.key,self.ledger)
  with self.assertRaisesRegex(ValueError,"equivocation"):
   restarted.approve({**self.payload,"new_key":"f"*64},self.policy)

 def test_ledger_file_is_private(self):
  import os,stat
  self.assertEqual(stat.S_IMODE(os.stat(self.ledger).st_mode),0o600)
 def test_insecure_existing_ledger_permissions_are_rejected(self):
  import os,pathlib
  path=str(pathlib.Path(self.temp.name)/"insecure.sqlite")
  pathlib.Path(path).write_bytes(b"")
  os.chmod(path,0o644)
  with self.assertRaisesRegex(ValueError,"private regular file"):
   RecoveryAuthoritySigner("authority-0",self.key,path)
 def test_symlink_ledger_path_is_rejected(self):
  import pathlib
  target=str(pathlib.Path(self.temp.name)/"target.sqlite")
  pathlib.Path(target).write_bytes(b"")
  link=str(pathlib.Path(self.temp.name)/"link.sqlite")
  pathlib.Path(link).symlink_to(target)
  with self.assertRaisesRegex(ValueError,"private regular file"):
   RecoveryAuthoritySigner("authority-0",self.key,link)


 def test_snapshot_rollback_demonstrates_local_guard_limit(self):
  import shutil,pathlib
  snapshot=str(pathlib.Path(self.temp.name)/"before-approval.sqlite")
  shutil.copy2(self.ledger,snapshot)
  first=self.signer.approve(self.payload,self.policy)
  shutil.copy2(snapshot,self.ledger)
  restarted=RecoveryAuthoritySigner("authority-0",self.key,self.ledger)
  conflicting={**self.payload,"new_key":"9"*64}
  second=restarted.approve(conflicting,self.policy)
  from signed_receipt import canonical
  first_statement=DOMAIN+canonical({"policy_sha256":policy_digest(self.policy),"payload_sha256":payload_digest(self.payload)})
  second_statement=DOMAIN+canonical({"policy_sha256":policy_digest(self.policy),"payload_sha256":payload_digest(conflicting)})
  self.key.public_key().verify(bytes.fromhex(first),first_statement)
  self.key.public_key().verify(bytes.fromhex(second),second_statement)
  self.assertNotEqual(first,second)

 def test_exported_approval_ledger_verifies_independently(self):
  from threshold_recovery import verify_approval_ledger
  self.signer.approve(self.payload,self.policy)
  bundle=self.signer.export_approval_ledger()
  self.assertTrue(verify_approval_ledger(bundle,self.key.public_key(),bundle["head_sha256"]))
 def test_approval_ledger_detects_event_tampering(self):
  from threshold_recovery import verify_approval_ledger
  self.signer.approve(self.payload,self.policy)
  bundle=self.signer.export_approval_ledger()
  bundle["events"][0]["payload_sha256"]="f"*64
  self.assertFalse(verify_approval_ledger(bundle,self.key.public_key()))
 def test_external_head_detects_ledger_tail_truncation(self):
  from threshold_recovery import verify_approval_ledger
  self.signer.approve(self.payload,self.policy)
  anchor=self.signer.export_approval_ledger()["head_sha256"]
  self.signer.approve({**self.payload,"generation":2,"previous_state_sha256":"c"*64},self.policy)
  truncated=self.signer.export_approval_ledger()
  truncated["events"]=truncated["events"][:1]
  truncated["head_sha256"]=truncated["events"][-1]["event_sha256"]
  self.assertTrue(verify_approval_ledger(truncated,self.key.public_key()))
  self.assertFalse(verify_approval_ledger(truncated,self.key.public_key(),self.signer.export_approval_ledger()["head_sha256"]))
  self.assertNotEqual(anchor,self.signer.export_approval_ledger()["head_sha256"])
 def test_idempotent_approval_does_not_append_second_event(self):
  self.signer.approve(self.payload,self.policy)
  first=self.signer.export_approval_ledger()
  self.signer.approve(self.payload,self.policy)
  second=self.signer.export_approval_ledger()
  self.assertEqual(first,second)


 def test_approval_ledger_rejects_boolean_sequence_number(self):
  from threshold_recovery import verify_approval_ledger
  self.signer.approve(self.payload,self.policy)
  bundle=self.signer.export_approval_ledger()
  bundle["events"][0]["sequence"]=True
  self.assertFalse(verify_approval_ledger(bundle,self.key.public_key()))
 def test_approval_ledger_rejects_malformed_digest_types(self):
  from threshold_recovery import verify_approval_ledger
  self.signer.approve(self.payload,self.policy)
  bundle=self.signer.export_approval_ledger()
  bundle["events"][0]["previous_state_sha256"]=123
  self.assertFalse(verify_approval_ledger(bundle,self.key.public_key()))

class RecoveryQuorumModelTests(unittest.TestCase):
 def test_safe_thresholds_exhaustively_for_councils_four_through_nine(self):
  from recovery_quorum_model import exhaustively_check
  for n in range(4,10):
   f=(n-1)//3
   q=(n+f)//2+1
   result=exhaustively_check(n,q,f)
   self.assertTrue(result["safe"],result)
   self.assertGreater(result["minimum_intersection"],f)
   self.assertLessEqual(q,n-f)
 def test_unsafe_two_of_four_has_concrete_conflicting_quorums(self):
  from recovery_quorum_model import exhaustively_check
  result=exhaustively_check(4,2,1)
  self.assertFalse(result["safe"])
  self.assertEqual(result["minimum_intersection"],0)
  self.assertEqual(result["counterexample"]["intersection"],[])
  self.assertEqual(result["counterexample"]["byzantine_set"],[])
 def test_boundary_threshold_has_honest_intersection(self):
  from recovery_quorum_model import exhaustively_check
  result=exhaustively_check(4,3,1)
  self.assertTrue(result["safe"])
  self.assertEqual(result["minimum_intersection"],2)

 def test_bounded_quorum_intersection_for_small_classical_bft_councils(self):
  import itertools
  for n in range(4,10):
   for faults in range(1,(n-1)//3+1):
    for quorum in range((n+faults)//2+1,n-faults+1):
     members=range(n)
     sets=list(itertools.combinations(members,quorum))
     for left,right in itertools.combinations(sets,2):
      self.assertGreater(len(set(left)&set(right)),faults,
       msg=f"n={n}, f={faults}, q={quorum}")



class ThresholdEnvelopeParsingTests(unittest.TestCase):
 def setUp(self):
  import tempfile,pathlib
  from witness_key_recovery import key_fingerprint
  self.temp=tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
  self.authorities={f"council-{i}":Ed25519PrivateKey.generate() for i in range(4)}
  self.policy=make_policy(self.authorities,3)
  self.old=Ed25519PrivateKey.generate(); self.new=Ed25519PrivateKey.generate()
  checkpoint={"schema":"AML-SEF2-SIGNED-HISTORY-CHECKPOINT-V1","epoch":1,"head_hash":"a"*64,"count":1,"approver_key_id":"c"*64}
  state={"witness_id":"north","generation":0,
   "public_key_sha256":key_fingerprint(self.old.public_key().public_bytes_raw().hex()),
   "checkpoint":checkpoint,"transition_sha256":"0"*64}
  signers={aid:RecoveryAuthoritySigner(aid,key,str(pathlib.Path(self.temp.name)/(aid+".sqlite")))
   for aid,key in self.authorities.items()}
  self.transition=make_threshold_transition(self.new,"north",state,
   {**checkpoint,"epoch":2,"head_hash":"b"*64,"count":2},self.policy,
   {k:signers[k] for k in ("council-0","council-1","council-2")})
 def test_threshold_adapter_rejects_duplicate_json_keys(self):
  from cryptography.exceptions import InvalidSignature
  from threshold_recovery import ThresholdRecoveryPublicKey
  from witness_key_recovery import AUTH_DOMAIN
  from signed_receipt import canonical
  verifier=ThresholdRecoveryPublicKey(self.policy)
  message=AUTH_DOMAIN+canonical(self.transition["payload"])
  with self.assertRaises(InvalidSignature):
   verifier.verify(b'{"schema":"A","schema":"B"}',message)
 def test_threshold_adapter_rejects_noncanonical_bundle_encoding(self):
  from cryptography.exceptions import InvalidSignature
  from threshold_recovery import ThresholdRecoveryPublicKey
  from witness_key_recovery import AUTH_DOMAIN
  from signed_receipt import canonical
  verifier=ThresholdRecoveryPublicKey(self.policy)
  message=AUTH_DOMAIN+canonical(self.transition["payload"])
  with self.assertRaises(InvalidSignature):
   verifier.verify(bytes.fromhex(self.transition["recovery_signature"])+b" ",message)
 def test_threshold_adapter_rejects_duplicate_payload_json_keys(self):
  from cryptography.exceptions import InvalidSignature
  from threshold_recovery import ThresholdRecoveryPublicKey
  from witness_key_recovery import AUTH_DOMAIN
  verifier=ThresholdRecoveryPublicKey(self.policy)
  with self.assertRaises(InvalidSignature):
   verifier.verify(bytes.fromhex(self.transition["recovery_signature"]),
    AUTH_DOMAIN+b'{"witness_id":"north","witness_id":"south"}')

class RecoveryLedgerAnchorTests(unittest.TestCase):
 def setUp(self):
  import tempfile,pathlib
  from recovery_ledger_anchor import ledger_checkpoint,checkpoint_pin
  self.temp=tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
  self.ledger=str(pathlib.Path(self.temp.name)/"authority.sqlite")
  self.key=Ed25519PrivateKey.generate()
  keys={"authority-0":self.key,"authority-1":Ed25519PrivateKey.generate(),
   "authority-2":Ed25519PrivateKey.generate(),"authority-3":Ed25519PrivateKey.generate()}
  self.policy=make_policy(keys,3)
  self.signer=RecoveryAuthoritySigner("authority-0",self.key,self.ledger)
  self.payload={"witness_id":"north","generation":1,"previous_state_sha256":"a"*64,"new_key":"b"*64}
  self.signer.approve(self.payload,self.policy)
  self.public_hex=self.key.public_key().public_bytes_raw().hex()
  self.checkpoint=ledger_checkpoint(self.ledger,"authority-0",self.public_hex)
  self.pin=checkpoint_pin(self.checkpoint)
 def test_independent_pin_accepts_unchanged_signed_ledger(self):
  from recovery_ledger_anchor import verify_ledger_checkpoint
  self.assertTrue(verify_ledger_checkpoint(self.ledger,self.public_hex,self.checkpoint,self.pin))
 def test_ledger_rollback_detected_against_external_checkpoint(self):
  import shutil,pathlib
  from recovery_ledger_anchor import verify_ledger_checkpoint,ledger_checkpoint
  snapshot=str(pathlib.Path(self.temp.name)/"approved.sqlite")
  shutil.copy2(self.ledger,snapshot)
  changed={**self.payload,"generation":2,"previous_state_sha256":"c"*64,"new_key":"d"*64}
  self.signer.approve(changed,self.policy)
  latest=ledger_checkpoint(self.ledger,"authority-0",self.public_hex)
  latest_pin=__import__("recovery_ledger_anchor").checkpoint_pin(latest)
  self.assertTrue(verify_ledger_checkpoint(self.ledger,self.public_hex,latest,latest_pin))
  shutil.copy2(snapshot,self.ledger)
  self.assertFalse(verify_ledger_checkpoint(self.ledger,self.public_hex,latest,latest_pin))
 def test_tampered_signature_rejected_even_with_recomputed_checkpoint_pin(self):
  import sqlite3
  from recovery_ledger_anchor import verify_ledger_checkpoint,ledger_checkpoint,checkpoint_pin
  with sqlite3.connect(self.ledger) as con:
   con.execute("UPDATE recovery_approval_ledger_v4 SET signature=?",( "00"*64,))
  changed=ledger_checkpoint(self.ledger,"authority-0",self.public_hex)
  self.assertFalse(verify_ledger_checkpoint(self.ledger,self.public_hex,changed,checkpoint_pin(changed)))
 def test_wrong_authority_public_key_rejected(self):
  from recovery_ledger_anchor import verify_ledger_checkpoint
  wrong=Ed25519PrivateKey.generate().public_key().public_bytes_raw().hex()
  self.assertFalse(verify_ledger_checkpoint(self.ledger,wrong,self.checkpoint,self.pin))
 def test_external_pin_tampering_rejected(self):
  from recovery_ledger_anchor import verify_ledger_checkpoint
  self.assertFalse(verify_ledger_checkpoint(self.ledger,self.public_hex,self.checkpoint,"0"*64))

 def test_authority_refuses_equivocation_across_competing_parent_forks(self):
  self.signer.approve(self.payload,self.policy)
  fork={**self.payload,"previous_state_sha256":"f"*64,"new_key":"c"*64}
  with self.assertRaisesRegex(ValueError,"equivocation"):
   self.signer.approve(fork,self.policy)
 def test_authority_refuses_policy_revision_reuse_for_same_generation(self):
  self.signer.approve(self.payload,self.policy)
  revised=dict(self.policy)
  revised["authorities"]["authority-3"]=Ed25519PrivateKey.generate().public_key().public_bytes_raw().hex()
  with self.assertRaisesRegex(ValueError,"equivocation"):
   self.signer.approve(self.payload,revised)

 def test_event_chain_verifies_against_external_pin(self):
  from recovery_ledger_anchor import event_chain_checkpoint,verify_event_chain,checkpoint_pin
  checkpoint=event_chain_checkpoint(self.ledger,"authority-0",self.public_hex)
  self.assertTrue(verify_event_chain(self.ledger,self.public_hex,checkpoint,checkpoint_pin(checkpoint)))
 def test_event_chain_detects_event_tampering(self):
  import sqlite3
  from recovery_ledger_anchor import event_chain_checkpoint,verify_event_chain,checkpoint_pin
  checkpoint=event_chain_checkpoint(self.ledger,"authority-0",self.public_hex)
  with sqlite3.connect(self.ledger) as con:
   con.execute("UPDATE recovery_approval_events SET payload_sha256=? WHERE sequence=1",("f"*64,))
  self.assertFalse(verify_event_chain(self.ledger,self.public_hex,checkpoint,checkpoint_pin(checkpoint)))
 def test_event_chain_detects_rollback_against_later_external_pin(self):
  import shutil,pathlib
  from recovery_ledger_anchor import event_chain_checkpoint,verify_event_chain,checkpoint_pin
  snapshot=str(pathlib.Path(self.temp.name)/"event-snapshot.sqlite")
  shutil.copy2(self.ledger,snapshot)
  self.signer.approve({**self.payload,"generation":2,"previous_state_sha256":"c"*64},self.policy)
  latest=event_chain_checkpoint(self.ledger,"authority-0",self.public_hex)
  pin=checkpoint_pin(latest)
  self.assertTrue(verify_event_chain(self.ledger,self.public_hex,latest,pin))
  shutil.copy2(snapshot,self.ledger)
  self.assertFalse(verify_event_chain(self.ledger,self.public_hex,latest,pin))

 def test_quorum_model_reports_safety_and_liveness_separately(self):
  from recovery_quorum_model import exhaustively_check
  result=exhaustively_check(4,4,1)
  self.assertTrue(result["intersection_safe"])
  self.assertFalse(result["liveness"])
  self.assertFalse(result["safe"])
 def test_quorum_model_rejects_fault_bound_outside_classical_bft_model(self):
  from recovery_quorum_model import exhaustively_check
  result=exhaustively_check(4,4,2)
  self.assertTrue(result["intersection_safe"])
  self.assertFalse(result["fault_bound_valid"])
  self.assertFalse(result["safe"])

 def test_ledger_cannot_be_reused_by_another_authority_identity(self):
  other=Ed25519PrivateKey.generate()
  with self.assertRaisesRegex(ValueError,"another authority identity"):
   RecoveryAuthoritySigner("authority-1",other,self.ledger)

 def test_authority_refuses_second_parent_fork_for_same_generation(self):
  self.signer.approve(self.payload,self.policy)
  fork={**self.payload,"previous_state_sha256":"c"*64,"new_key":"d"*64}
  with self.assertRaisesRegex(ValueError,"equivocation"):
   self.signer.approve(fork,self.policy)
 def test_authority_refuses_policy_revision_reuse_for_same_generation(self):
  self.signer.approve(self.payload,self.policy)
  revised=copy.deepcopy(self.policy)
  revised["authorities"]["authority-3"]=Ed25519PrivateKey.generate().public_key().public_bytes_raw().hex()
  with self.assertRaisesRegex(ValueError,"equivocation"):
   self.signer.approve(self.payload,revised)
 def test_recovery_ledger_is_scoped_to_authority_and_witness_generation(self):
  self.signer.approve(self.payload,self.policy)
  other={**self.payload,"witness_id":"south"}
  self.assertNotEqual(self.signer.approve(other,self.policy),
      self.signer.approve(self.payload,self.policy))

class BoundedRecoveryStateModelTests(unittest.TestCase):
 def test_three_of_four_with_one_byzantine_excludes_conflicting_commits(self):
  from recovery_quorum_model import model_check_conflicting_commits,bounded_recovery_state_check
  self.assertIsNone(model_check_conflicting_commits(4,3,1))
  result=bounded_recovery_state_check(4,3,1)
  self.assertTrue(result["safe"])
  self.assertTrue(result["predecessor_revoked"])
  self.assertTrue(result["replay_excluded"])
  self.assertTrue(result["stale_fork_excluded"])
 def test_two_of_four_exposes_concrete_conflicting_commit_counterexample(self):
  from recovery_quorum_model import model_check_conflicting_commits
  result=model_check_conflicting_commits(4,2,1)
  self.assertIsNotNone(result)
  self.assertLessEqual(len(result["byzantine"]),1)
  self.assertEqual(result["first_payload"],"A")
  self.assertEqual(result["second_payload"],"B")
 def test_bounded_state_model_rejects_faulty_quorum_even_when_transition_shape_is_valid(self):
  from recovery_quorum_model import bounded_recovery_state_check
  result=bounded_recovery_state_check(4,2,1)
  self.assertFalse(result["safe"])
  self.assertIsNotNone(result["conflicting_commit_counterexample"])

class RecoveryAuthorityConcurrencyTests(unittest.TestCase):
 def setUp(self):
  import pathlib,tempfile
  self.temp=tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
  self.keys={f"authority-{i}":Ed25519PrivateKey.generate() for i in range(4)}
  self.policy=make_policy(self.keys,3)
  self.ledger=str(pathlib.Path(self.temp.name)/"authority.sqlite")
  self.signers=[RecoveryAuthoritySigner("authority-0",self.keys["authority-0"],self.ledger)
      for _ in range(2)]
  self.payload={"witness_id":"north","generation":9,"previous_state_sha256":"a"*64,"next_policy_sha256":"b"*64}
 def test_concurrent_conflicting_approvals_have_exactly_one_winner(self):
  import concurrent.futures,threading
  barrier=threading.Barrier(2)
  payloads=[self.payload,{**self.payload,"previous_state_sha256":"c"*64,"next_policy_sha256":"d"*64}]
  def submit(i):
   barrier.wait()
   try: return ("approved",self.signers[i].approve(payloads[i],self.policy))
   except ValueError as exc: return ("refused",str(exc))
  with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
   results=list(pool.map(submit,(0,1)))
  self.assertEqual(sum(status=="approved" for status,_ in results),1)
  self.assertEqual(sum(status=="refused" for status,_ in results),1)
  self.assertIn("equivocation",[value for status,value in results if status=="refused"][0])
 def test_concurrent_identical_approvals_are_idempotent(self):
  import concurrent.futures,threading
  barrier=threading.Barrier(2)
  def submit(signer):
   barrier.wait()
   return signer.approve(self.payload,self.policy)
  with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
   signatures=list(pool.map(submit,self.signers))
  self.assertEqual(signatures[0],signatures[1])
  self.assertEqual(len(signatures[0]),128)

 def test_separate_processes_cannot_commit_conflicting_approvals(self):
  import json,os,pathlib,subprocess,sys,time
  from cryptography.hazmat.primitives import serialization
  # Initialize schema and authority identity before racing the independent clients.
  private_raw=self.keys["authority-0"].private_bytes(
   serialization.Encoding.Raw,serialization.PrivateFormat.Raw,serialization.NoEncryption()).hex()
  ready=[str(pathlib.Path(self.temp.name)/f"ready-{i}") for i in range(2)]
  go=str(pathlib.Path(self.temp.name)/"go")
  payloads=[self.payload,{**self.payload,"previous_state_sha256":"e"*64,"next_policy_sha256":"f"*64}]
  code="""import json,os,sys,time
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from threshold_recovery import RecoveryAuthoritySigner
ledger,aid,private_hex,policy_json,payload_json,ready,go=sys.argv[1:]
key=Ed25519PrivateKey.from_private_bytes(bytes.fromhex(private_hex))
signer=RecoveryAuthoritySigner(aid,key,ledger)
open(ready,'w').close()
deadline=time.monotonic()+10
while not os.path.exists(go):
 if time.monotonic()>deadline: raise SystemExit(3)
 time.sleep(.005)
try:
 signature=signer.approve(json.loads(payload_json),json.loads(policy_json))
 print(json.dumps({'status':'approved','signature':signature}))
except ValueError as exc:
 print(json.dumps({'status':'refused','reason':str(exc)}))
"""
  procs=[]
  for i in range(2):
   args=[sys.executable,"-c",code,self.ledger,"authority-0",private_raw,
      json.dumps(self.policy),json.dumps(payloads[i]),ready[i],go]
   procs.append(subprocess.Popen(args,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True))
  deadline=time.monotonic()+10
  while not all(os.path.exists(path) for path in ready):
   if time.monotonic()>deadline:
    for p in procs: p.kill()
    self.fail("subprocess approval clients did not reach start barrier")
   time.sleep(.005)
  pathlib.Path(go).touch()
  results=[]
  for proc in procs:
   stdout,stderr=proc.communicate(timeout=15)
   self.assertEqual(proc.returncode,0,stderr)
   results.append(json.loads(stdout.strip()))
  self.assertEqual(sum(item["status"]=="approved" for item in results),1)
  refused=[item for item in results if item["status"]=="refused"]
  self.assertEqual(len(refused),1)
  self.assertIn("equivocation",refused[0]["reason"])

 def test_crash_after_commit_before_response_is_idempotently_recoverable(self):
  import json,subprocess,sys
  from cryptography.hazmat.primitives import serialization
  from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
  from threshold_recovery import DOMAIN
  from signed_receipt import canonical
  private_raw=self.keys["authority-0"].private_bytes(
   serialization.Encoding.Raw,serialization.PrivateFormat.Raw,serialization.NoEncryption()).hex()
  code="""import json,os,sys
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from threshold_recovery import RecoveryAuthoritySigner
ledger,private_hex,policy_json,payload_json=sys.argv[1:]
signer=RecoveryAuthoritySigner('authority-0',Ed25519PrivateKey.from_private_bytes(bytes.fromhex(private_hex)),ledger)
signer.approve(json.loads(payload_json),json.loads(policy_json))
os._exit(77)  # durable commit completed; simulated response lost with process death
"""
  proc=subprocess.run([sys.executable,"-c",code,self.ledger,private_raw,
      json.dumps(self.policy),json.dumps(self.payload)],capture_output=True,text=True,timeout=15)
  self.assertEqual(proc.returncode,77,proc.stderr)
  recovered=RecoveryAuthoritySigner("authority-0",self.keys["authority-0"],self.ledger).approve(self.payload,self.policy)
  statement=DOMAIN+canonical({"policy_sha256":__import__("threshold_recovery").policy_digest(self.policy),
      "payload_sha256":__import__("threshold_recovery").payload_digest(self.payload)})
  Ed25519PublicKey.from_public_bytes(self.keys["authority-0"].public_key().public_bytes_raw()).verify(
      bytes.fromhex(recovered),statement)

class RecoveryLedgerVerifierEquivocationTests(unittest.TestCase):
 def test_export_verifier_rejects_same_generation_reauthorized_under_new_policy(self):
  import hashlib
  from signed_receipt import canonical
  from threshold_recovery import DOMAIN,verify_approval_ledger
  key=Ed25519PrivateKey.generate(); events=[]; previous="0"*64
  for seq,policy_id in ((1,"policy-old"),(2,"policy-new")):
   pd=hashlib.sha256(policy_id.encode()).hexdigest()
   payload_sha=hashlib.sha256((policy_id+"payload").encode()).hexdigest()
   signature=key.sign(DOMAIN+canonical({"policy_sha256":pd,"payload_sha256":payload_sha})).hex()
   event={"sequence":seq,"previous_event_sha256":previous,"policy_id":policy_id,
    "authority_id":"authority-A","witness_id":"north","generation":4,
    "policy_sha256":pd,"previous_state_sha256":"a"*64,
    "payload_sha256":payload_sha,"signature":signature}
   event["event_sha256"]=hashlib.sha256(canonical(event)).hexdigest()
   previous=event["event_sha256"]; events.append(event)
  bundle={"schema":"AML-SEF2-RECOVERY-APPROVAL-LEDGER-V1",
   "authority_id":"authority-A","events":events,"head_sha256":previous}
  self.assertFalse(verify_approval_ledger(bundle,key.public_key(),previous))

class IndependentlyAnchoredRecoveryLedgerTests(unittest.TestCase):
 def setUp(self):
  import pathlib,tempfile
  from threshold_recovery import MemoryRecoveryHeadAnchor,RecoveryAuthoritySigner
  self.temp=tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
  self.key=Ed25519PrivateKey.generate()
  self.keys={"authority-0":self.key,**{f"authority-{i}":Ed25519PrivateKey.generate() for i in range(1,4)}}
  self.policy=make_policy(self.keys,3)
  self.path=str(pathlib.Path(self.temp.name)/"anchored.sqlite")
  self.anchor=MemoryRecoveryHeadAnchor()
  self.signer=RecoveryAuthoritySigner("authority-0",self.key,self.path,head_anchor=self.anchor)
  self.payload={"witness_id":"north","generation":1,"previous_state_sha256":"a"*64,"next_policy_sha256":"b"*64}
 def test_approval_advances_external_anchor_to_ledger_head(self):
  self.signer.approve(self.payload,self.policy)
  self.assertEqual(self.anchor.read_head(),self.signer.export_approval_ledger()["head_sha256"])
 def test_snapshot_rollback_is_detected_by_independent_anchor(self):
  import shutil,pathlib
  from threshold_recovery import RecoveryAuthoritySigner
  snapshot=str(pathlib.Path(self.temp.name)/"empty-snapshot.sqlite")
  shutil.copy2(self.path,snapshot)
  self.signer.approve(self.payload,self.policy)
  shutil.copy2(snapshot,self.path)
  with self.assertRaisesRegex(RuntimeError,"differs from independent anchor"):
   RecoveryAuthoritySigner("authority-0",self.key,self.path,head_anchor=self.anchor)
 def test_anchor_disagreement_prevents_new_approval(self):
  self.signer.approve(self.payload,self.policy)
  current=self.anchor.read_head()
  self.assertTrue(self.anchor.compare_and_set(current,"f"*64))
  with self.assertRaisesRegex(RuntimeError,"differs from independent anchor"):
   self.signer.approve({**self.payload,"generation":2},self.policy)
 def test_anchor_cas_race_leaves_local_commit_fail_closed(self):
  class RefusingAnchor:
   def __init__(self): self.head="0"*64
   def read_head(self): return self.head
   def compare_and_set(self,expected,new):
    if expected=="0"*64 and new=="0"*64: return True
    return False
  from threshold_recovery import RecoveryAuthoritySigner
  anchor=RefusingAnchor()
  signer=RecoveryAuthoritySigner("authority-0",self.key,self.path,head_anchor=anchor)
  with self.assertRaisesRegex(RuntimeError,"committed locally"):
   signer.approve(self.payload,self.policy)
  with self.assertRaisesRegex(RuntimeError,"cannot initialize|differs from independent anchor"):
   RecoveryAuthoritySigner("authority-0",self.key,self.path,head_anchor=anchor)
 def test_nonempty_ledger_cannot_bootstrap_new_anchor(self):
  from threshold_recovery import RecoveryAuthoritySigner,MemoryRecoveryHeadAnchor
  unanchored=RecoveryAuthoritySigner("authority-0",self.key,self.path)
  unanchored.approve(self.payload,self.policy)
  with self.assertRaisesRegex(RuntimeError,"cannot initialize"):
   RecoveryAuthoritySigner("authority-0",self.key,self.path,head_anchor=MemoryRecoveryHeadAnchor())

class QuorumRecoveryHeadAnchorTests(unittest.TestCase):
 def setUp(self):
  from threshold_recovery import MemoryRecoveryHeadAnchor,QuorumRecoveryHeadAnchor
  self.replicas=[MemoryRecoveryHeadAnchor(f"anchor-{i}") for i in range(4)]
  self.quorum=QuorumRecoveryHeadAnchor(self.replicas,3,1)
  self.old="0"*64; self.new="a"*64
 def test_three_of_four_anchors_accept_head_transition(self):
  self.assertTrue(self.quorum.compare_and_set(self.old,self.new))
  self.assertEqual(self.quorum.read_head(),self.new)
 def test_one_unavailable_anchor_does_not_prevent_quorum(self):
  class Down:
   anchor_id="anchor-down"
   def read_head(self): raise OSError("offline")
   def compare_and_set(self,*args): raise OSError("offline")
  from threshold_recovery import QuorumRecoveryHeadAnchor
  q=QuorumRecoveryHeadAnchor(self.replicas[:3]+[Down()],3,1)
  self.assertTrue(q.compare_and_set(self.old,self.new))
  self.assertEqual(q.read_head(),self.new)
 def test_conflicting_head_without_quorum_fails_closed(self):
  for replica,head in zip(self.replicas,("a"*64,"b"*64,"c"*64,"d"*64)):
   replica.compare_and_set(self.old,head)
  with self.assertRaisesRegex(RuntimeError,"no unique quorum"):
   self.quorum.read_head()
 def test_invalid_quorum_bounds_are_rejected(self):
  from threshold_recovery import QuorumRecoveryHeadAnchor
  with self.assertRaises(ValueError): QuorumRecoveryHeadAnchor(self.replicas,2,1)
  with self.assertRaises(ValueError): QuorumRecoveryHeadAnchor(self.replicas,4,1)
 def test_concurrent_conflicting_head_updates_cannot_both_reach_quorum(self):
  import concurrent.futures,threading
  barrier=threading.Barrier(2)
  candidates=["a"*64,"b"*64]
  def update(candidate):
   barrier.wait()
   return self.quorum.compare_and_set(self.old,candidate)
  with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
   results=list(pool.map(update,candidates))
  self.assertEqual(sum(results),1)
  self.assertIn(self.quorum.read_head(),candidates)
 def test_partial_anchor_update_can_be_completed_idempotently(self):
  class FailOnce:
   def __init__(self,inner): self.inner=inner; self.anchor_id=inner.anchor_id; self.fail=True
   def read_head(self): return self.inner.read_head()
   def compare_and_set(self,old,new):
    if self.fail:
     self.fail=False
     return False
    return self.inner.compare_and_set(old,new)
  from threshold_recovery import QuorumRecoveryHeadAnchor
  anchors=[FailOnce(self.replicas[0]),FailOnce(self.replicas[1]),
      self.replicas[2],self.replicas[3]]
  q=QuorumRecoveryHeadAnchor(anchors,3,1)
  self.assertFalse(q.compare_and_set(self.old,self.new))
  self.assertTrue(q.compare_and_set(self.old,self.new))
  self.assertEqual(q.read_head(),self.new)
 def test_signer_uses_quorum_anchor_for_rollback_detection(self):
  import pathlib,tempfile,shutil
  from threshold_recovery import RecoveryAuthoritySigner
  with tempfile.TemporaryDirectory() as directory:
   key=Ed25519PrivateKey.generate()
   keys={"authority-0":key,**{f"authority-{i}":Ed25519PrivateKey.generate() for i in range(1,4)}}
   policy=make_policy(keys,3); path=str(pathlib.Path(directory)/"ledger.sqlite")
   signer=RecoveryAuthoritySigner("authority-0",key,path,head_anchor=self.quorum)
   payload={"witness_id":"north","generation":1,"previous_state_sha256":"a"*64}
   signer.approve(payload,policy)
   self.assertEqual(self.quorum.read_head(),signer.export_approval_ledger()["head_sha256"])

class SignedRecoveryHeadAnchorTests(unittest.TestCase):
 def setUp(self):
  from threshold_recovery import (RECOVERY_ANCHOR_READ_DOMAIN,RECOVERY_ANCHOR_CAS_DOMAIN,
      SignedRecoveryHeadAnchor)
  from signed_receipt import canonical
  self.read_domain=RECOVERY_ANCHOR_READ_DOMAIN; self.cas_domain=RECOVERY_ANCHOR_CAS_DOMAIN
  self.canonical=canonical; self.key=Ed25519PrivateKey.generate()
  class Server:
   def __init__(inner): inner.head="0"*64
   def read_head(inner,nonce):
    body={"anchor_id":"anchor-east","head_sha256":inner.head,"nonce":nonce}
    return {**body,"signature":self.key.sign(self.read_domain+self.canonical(body)).hex()}
   def compare_and_set(inner,expected,new,nonce):
    accepted=inner.head==expected
    if accepted: inner.head=new
    body={"anchor_id":"anchor-east","expected_head":expected,"new_head":new,"accepted":accepted,"nonce":nonce}
    return {**body,"signature":self.key.sign(self.cas_domain+self.canonical(body)).hex()}
  self.server=Server()
  from threshold_recovery import SignedRecoveryHeadAnchor
  self.anchor=SignedRecoveryHeadAnchor("anchor-east",self.key.public_key(),self.server)
 def test_signed_nonce_bound_read_and_cas_succeed(self):
  old=self.anchor.read_head(); new="a"*64
  self.assertTrue(self.anchor.compare_and_set(old,new))
  self.assertEqual(self.anchor.read_head(),new)
 def test_wrong_pinned_key_rejects_signed_response(self):
  from threshold_recovery import SignedRecoveryHeadAnchor
  bad=SignedRecoveryHeadAnchor("anchor-east",Ed25519PrivateKey.generate().public_key(),self.server)
  with self.assertRaisesRegex(RuntimeError,"signature verification failed"): bad.read_head()
 def test_wrong_anchor_identity_rejected(self):
  from threshold_recovery import SignedRecoveryHeadAnchor
  bad=SignedRecoveryHeadAnchor("anchor-west",self.key.public_key(),self.server)
  with self.assertRaisesRegex(RuntimeError,"identity or freshness"): bad.read_head()
 def test_replayed_read_response_rejected_by_nonce(self):
  class Replay:
   def __init__(inner): inner.saved=None
   def read_head(inner,nonce):
    if inner.saved is None: inner.saved=self.server.read_head(nonce)
    return inner.saved
   def compare_and_set(inner,*args): return self.server.compare_and_set(*args)
  from threshold_recovery import SignedRecoveryHeadAnchor
  anchor=SignedRecoveryHeadAnchor("anchor-east",self.key.public_key(),Replay())
  self.assertEqual(anchor.read_head(),"0"*64)
  with self.assertRaisesRegex(RuntimeError,"identity or freshness"): anchor.read_head()
 def test_tampered_cas_result_rejected(self):
  class Tamper:
   def read_head(inner,nonce): return self.server.read_head(nonce)
   def compare_and_set(inner,expected,new,nonce):
    response=self.server.compare_and_set(expected,new,nonce)
    response["accepted"]=not response["accepted"]
    return response
  from threshold_recovery import SignedRecoveryHeadAnchor
  anchor=SignedRecoveryHeadAnchor("anchor-east",self.key.public_key(),Tamper())
  with self.assertRaisesRegex(RuntimeError,"binding mismatch|signature verification failed"):
   anchor.compare_and_set("0"*64,"b"*64)
 def test_replayed_cas_receipt_rejected_by_nonce(self):
  class Replay:
   def __init__(inner): inner.saved=None
   def read_head(inner,nonce): return self.server.read_head(nonce)
   def compare_and_set(inner,expected,new,nonce):
    if inner.saved is None: inner.saved=self.server.compare_and_set(expected,new,nonce)
    return inner.saved
  from threshold_recovery import SignedRecoveryHeadAnchor
  anchor=SignedRecoveryHeadAnchor("anchor-east",self.key.public_key(),Replay())
  self.assertTrue(anchor.compare_and_set("0"*64,"c"*64))
  with self.assertRaisesRegex(RuntimeError,"binding mismatch"):
   anchor.compare_and_set("c"*64,"d"*64)

 def test_duplicate_anchor_ids_are_rejected_even_for_distinct_instances(self):
  from threshold_recovery import MemoryRecoveryHeadAnchor,QuorumRecoveryHeadAnchor
  replicas=[MemoryRecoveryHeadAnchor("same") for _ in range(4)]
  with self.assertRaisesRegex(ValueError,"identities must be unique"):
   QuorumRecoveryHeadAnchor(replicas,3,1)
 def test_duplicate_ed25519_keys_are_rejected_under_different_anchor_ids(self):
  from threshold_recovery import SignedRecoveryHeadAnchor,QuorumRecoveryHeadAnchor
  key=Ed25519PrivateKey.generate()
  anchors=[SignedRecoveryHeadAnchor(f"anchor-{i}",key.public_key(),object()) for i in range(4)]
  with self.assertRaisesRegex(ValueError,"distinct public keys"):
   QuorumRecoveryHeadAnchor(anchors,3,1)
 def test_anchor_without_stable_identity_is_rejected(self):
  from threshold_recovery import QuorumRecoveryHeadAnchor
  class Anonymous:
   def read_head(self): return "0"*64
   def compare_and_set(self,*args): return True
  with self.assertRaisesRegex(ValueError,"stable anchor_id"):
   QuorumRecoveryHeadAnchor([Anonymous(),Anonymous(),Anonymous(),Anonymous()],3,1)
