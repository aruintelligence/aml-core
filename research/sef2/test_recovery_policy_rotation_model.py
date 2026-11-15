import itertools,unittest
from recovery_policy_rotation_model import check_rotation_model,dual_consent_commit_allowed

class RecoveryPolicyRotationModelTests(unittest.TestCase):
 def test_four_member_three_of_four_dual_consent_is_safe(self):
  r=check_rotation_model(4,3,1)
  self.assertTrue(r["safe"])
  self.assertEqual(r["minimum_old_intersection"],2)
  self.assertTrue(r["incoming_consent_available"])
  self.assertIsNone(r["conflict_counterexample"])
 def test_two_of_four_has_byzantine_intersection_counterexample(self):
  r=check_rotation_model(4,2,1)
  self.assertFalse(r["safe"])
  self.assertEqual(r["conflict_counterexample"]["intersection"],[0])
 def test_unanimous_four_of_four_is_safe_but_not_live_with_one_failure(self):
  r=check_rotation_model(4,4,1)
  self.assertTrue(r["old_council_conflict_free"])
  self.assertFalse(r["liveness"])
  self.assertFalse(r["safe"])
 def test_fault_bound_above_classical_bft_limit_rejected(self):
  r=check_rotation_model(4,3,2)
  self.assertFalse(r["fault_bound_valid"])
  self.assertFalse(r["safe"])
 def test_seven_member_five_of_seven_with_two_faults(self):
  r=check_rotation_model(7,5,2)
  self.assertTrue(r["safe"])
  self.assertGreater(r["minimum_old_intersection"],2)
 def test_bool_is_not_accepted_as_integer_model_bound(self):
  with self.assertRaises(ValueError): check_rotation_model(True,1,0)
 def test_commit_requires_outgoing_and_incoming_quorums(self):
  old=set(range(3)); new=set(range(4,7))
  self.assertTrue(dual_consent_commit_allowed(old,new,4,3))
  self.assertFalse(dual_consent_commit_allowed(old-{0},new,4,3))
  self.assertFalse(dual_consent_commit_allowed(old,new-{4},4,3))
 def test_duplicate_or_foreign_identities_cannot_inflate_quorum(self):
  self.assertFalse(dual_consent_commit_allowed({0,1,2,4},{4,5,6},4,3))
  self.assertFalse(dual_consent_commit_allowed({0,1,2},{4,5,6,0},4,3))
 def test_exhaustive_commit_gate_truth_table(self):
  old_sets=[set(c) for k in range(5) for c in itertools.combinations(range(4),k)]
  new_sets=[set(c) for k in range(5) for c in itertools.combinations(range(4,8),k)]
  for old in old_sets:
   for new in new_sets:
    expected=len(old)>=3 and len(new)>=3
    self.assertEqual(dual_consent_commit_allowed(old,new,4,3),expected)

 def test_boolean_authority_identifiers_are_not_integer_aliases(self):
  self.assertFalse(dual_consent_commit_allowed({True,1,2},{4,5,6},4,3))
