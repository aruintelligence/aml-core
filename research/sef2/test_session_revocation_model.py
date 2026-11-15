import unittest
from session_revocation_model import explore

class SessionRevocationModelTests(unittest.TestCase):
 def test_anchored_protocol_has_no_old_capability_resurrection_within_bound(self):
  self.assertEqual(explore(depth=10,broken_execute=False),[])
 def test_model_finds_counterexample_when_anchor_check_is_removed(self):
  violations=explore(depth=8,broken_execute=True)
  self.assertTrue(violations)
  path=violations[0]
  self.assertIn("anchor_commit",path)
  self.assertIn("rollback_local",path)
  self.assertEqual(path[-1],"execute_old_capability")
 def test_counterexample_is_short_and_reproducible(self):
  path=explore(depth=8,broken_execute=True)[0]
  self.assertLessEqual(len(path),8)
