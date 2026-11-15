import unittest
from recovery_anchor_rotation_model import analyze_anchor_succession,state_transfer_commit_allowed
class AnchorRotationModelTests(unittest.TestCase):
 def test_three_of_four_to_three_of_four_is_safe_for_one_fault_each(self):
  r=analyze_anchor_succession(4,3,1,4,3,1)
  self.assertTrue(r["safe"]); self.assertIsNone(r["old_counterexample"]); self.assertIsNone(r["new_counterexample"])
 def test_unsafe_outgoing_two_of_four_exposes_conflict(self):
  r=analyze_anchor_succession(4,2,1,4,3,1)
  self.assertFalse(r["safe"]); self.assertIsNotNone(r["old_counterexample"])
 def test_unsafe_incoming_two_of_four_exposes_conflict(self):
  r=analyze_anchor_succession(4,3,1,4,2,1)
  self.assertFalse(r["safe"]); self.assertIsNotNone(r["new_counterexample"])
 def test_unanimity_is_safe_but_not_live_with_one_fault(self):
  r=analyze_anchor_succession(4,4,1,4,4,1)
  self.assertTrue(r["old_safe"]); self.assertFalse(r["old_liveness"]); self.assertFalse(r["safe"])
 def test_state_transfer_requires_both_quorums_and_exact_state(self):
  old=set(range(4)); new=set(range(4,8)); oa={0,1,2}; na={4,5,6}
  self.assertTrue(state_transfer_commit_allowed(2,2,5,"a",5,"a",oa,na,old,new,3,3))
  self.assertFalse(state_transfer_commit_allowed(2,3,5,"a",5,"a",oa,na,old,new,3,3))
  self.assertFalse(state_transfer_commit_allowed(2,2,5,"a",4,"a",oa,na,old,new,3,3))
  self.assertFalse(state_transfer_commit_allowed(2,2,5,"a",5,"b",oa,na,old,new,3,3))
  self.assertFalse(state_transfer_commit_allowed(2,2,5,"a",5,"a",{0,1},na,old,new,3,3))
  self.assertFalse(state_transfer_commit_allowed(2,2,5,"a",5,"a",oa,{4,5},old,new,3,3))
 def test_foreign_signer_cannot_inflate_state_transfer_quorum(self):
  old=set(range(4)); new=set(range(4,8))
  self.assertFalse(state_transfer_commit_allowed(2,2,5,"a",5,"a",{0,1,9},{4,5,6},old,new,3,3))
 def test_invalid_bounds_rejected(self):
  with self.assertRaises(ValueError): analyze_anchor_succession(True,3,1,4,3,1)
