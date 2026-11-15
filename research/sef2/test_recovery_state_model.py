import itertools,unittest
from recovery_state_model import analyze_recovery_quorums,recovery_commit_allowed,explore_recovery_sequence

class RecoveryStateModelTests(unittest.TestCase):
 def test_three_of_four_one_fault_is_safe(self):
  r=analyze_recovery_quorums(4,3,1)
  self.assertTrue(r["safe"]); self.assertIsNone(r["counterexample"])
  self.assertEqual(r["minimum_intersection"],2)
 def test_two_of_four_has_conflicting_commit_counterexample(self):
  r=analyze_recovery_quorums(4,2,1)
  self.assertFalse(r["safe"]); self.assertIsNotNone(r["counterexample"])
 def test_four_of_four_safe_but_not_live_with_one_fault(self):
  r=analyze_recovery_quorums(4,4,1)
  self.assertTrue(r["conflicting_commit_impossible"]); self.assertFalse(r["liveness"]); self.assertFalse(r["safe"])
 def test_fault_bound_above_bft_limit_fails(self):
  self.assertFalse(analyze_recovery_quorums(4,3,2)["safe"])
 def test_five_of_seven_two_faults_is_safe(self):
  self.assertTrue(analyze_recovery_quorums(7,5,2)["safe"])
 def test_commit_requires_current_parent_and_next_generation(self):
  enrolled=set(range(4)); approvals={0,1,2}
  self.assertTrue(recovery_commit_allowed(5,"parent",6,"parent",approvals,enrolled,4,3))
  self.assertFalse(recovery_commit_allowed(5,"parent",5,"parent",approvals,enrolled,4,3))
  self.assertFalse(recovery_commit_allowed(5,"parent",7,"parent",approvals,enrolled,4,3))
  self.assertFalse(recovery_commit_allowed(5,"parent",6,"stale",approvals,enrolled,4,3))
 def test_duplicate_or_foreign_signer_cannot_inflate_quorum(self):
  enrolled=set(range(4))
  self.assertFalse(recovery_commit_allowed(0,"g",1,"g",{0,1,9},enrolled,4,3))
  self.assertFalse(recovery_commit_allowed(0,"g",1,"g",{0,1},enrolled,4,3))
 def test_exhaustive_signer_sets_match_threshold_gate(self):
  enrolled=set(range(4))
  for k in range(6):
   for combo in itertools.combinations(range(5),k):
    approvals=set(combo)
    expected=approvals<=enrolled and len(approvals)>=3
    self.assertEqual(recovery_commit_allowed(0,"g",1,"g",approvals,enrolled,4,3),expected)
 def test_bounded_sequence_advances_monotonically(self):
  r=explore_recovery_sequence(5)
  self.assertEqual(r["max_generation"],5); self.assertGreater(r["edges"],5)
 def test_invalid_model_bounds_rejected(self):
  with self.assertRaises(ValueError): analyze_recovery_quorums(True,3,1)
  with self.assertRaises(ValueError): explore_recovery_sequence(0)


class RecoveryPolicyImplementationConsistencyTests(unittest.TestCase):
 def test_every_bounded_policy_accepted_by_implementation_is_model_safe(self):
  from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
  from threshold_recovery import POLICY_SCHEMA,validate_policy
  for n in range(1,9):
   keys={f"a{i}":Ed25519PrivateKey.generate().public_key().public_bytes_raw().hex() for i in range(n)}
   domains={name:"domain-"+name for name in keys}
   for f in range(0,n+1):
    for q in range(1,n+1):
     policy={"schema":POLICY_SCHEMA,"policy_id":f"p-{n}-{q}-{f}",
       "threshold":q,"max_faults":f,"authorities":keys,
       "administrative_domains":domains}
     accepted=validate_policy(policy)
     modeled=analyze_recovery_quorums(n,q,f)["safe"]
     self.assertEqual(accepted,modeled,(n,q,f))

 def test_known_unsafe_configurations_remain_rejected(self):
  from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
  from threshold_recovery import POLICY_SCHEMA,validate_policy
  for n,q,f in ((3,2,1),(4,2,1),(4,4,1),(6,4,2)):
   keys={f"a{i}":Ed25519PrivateKey.generate().public_key().public_bytes_raw().hex() for i in range(n)}
   policy={"schema":POLICY_SCHEMA,"policy_id":"unsafe","threshold":q,"max_faults":f,
      "authorities":keys,"administrative_domains":{name:"d-"+name for name in keys}}
   self.assertFalse(validate_policy(policy),(n,q,f))
