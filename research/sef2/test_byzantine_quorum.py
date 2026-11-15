import unittest
from quorum_model import validate_bft_quorum,enumerate_quorum_intersections

class ByzantineQuorumTests(unittest.TestCase):
    def test_three_of_four_tolerates_one_byzantine_identity(self):
        model=validate_bft_quorum(4,3,1)
        self.assertEqual(model["minimum_quorum_intersection"],2)
        self.assertEqual(model["minimum_honest_intersection"],1)
    def test_two_of_three_is_not_one_byzantine_safe(self):
        with self.assertRaises(ValueError): validate_bft_quorum(3,2,1)
    def test_two_of_three_is_crash_only_when_fault_bound_is_zero(self):
        self.assertEqual(validate_bft_quorum(3,2,0)["max_byzantine_faults"],0)
    def test_four_witness_quorum_pairwise_intersection(self):
        intersections=enumerate_quorum_intersections(("north","south","east","west"),3)
        self.assertEqual(len(intersections),6)
        self.assertEqual(min(intersections),2)
        self.assertTrue(all(size>=2 for size in intersections))
    def test_one_fault_liveness_requires_three_of_four(self):
        with self.assertRaises(ValueError): validate_bft_quorum(4,4,1)
    def test_fault_bound_requires_three_f_plus_one_members(self):
        with self.assertRaises(ValueError): validate_bft_quorum(6,5,2)
    def test_seven_members_five_quorum_tolerates_two_faults(self):
        self.assertEqual(validate_bft_quorum(7,5,2)["minimum_honest_intersection"],1)
    def test_boolean_parameters_rejected(self):
        with self.assertRaises(ValueError): validate_bft_quorum(4,3,True)
    def test_duplicate_identity_rejected(self):
        with self.assertRaises(ValueError): enumerate_quorum_intersections(("a","b","b","d"),3)
