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
