import copy,unittest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from threshold_recovery import POLICY_SCHEMA,make_approval_bundle,make_threshold_transition,validate_policy,verify_approval_bundle
def make_policy(keys,threshold=2):
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
  self.transition=make_threshold_transition(self.new,"north",self.state,self.next_checkpoint,
    self.policy,{k:self.authorities[k] for k in ("council-0","council-1","council-2")})
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
