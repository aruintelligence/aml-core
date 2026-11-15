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
