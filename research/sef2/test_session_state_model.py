import unittest
from session_state_model import explore,commit_allowed

class SessionStateModelTests(unittest.TestCase):
 def test_bounded_state_graph_has_only_authorized_commits(self):
  result=explore()
  self.assertGreater(result["states"],5)
  self.assertGreater(result["edges"],10)
  self.assertGreaterEqual(len(result["commit_traces"]),1)
 def test_copied_capability_without_holder_key_cannot_commit(self):
  self.assertFalse(commit_allowed(0,0,0,True,False,False))
 def test_revoked_capability_cannot_commit(self):
  self.assertFalse(commit_allowed(1,0,0,True,True,False))
 def test_stale_challenge_after_revocation_cannot_commit(self):
  self.assertFalse(commit_allowed(1,1,0,True,True,False))
 def test_current_capability_current_challenge_holder_can_commit(self):
  self.assertTrue(commit_allowed(1,1,1,True,True,False))
 def test_consumed_challenge_cannot_commit_again(self):
  self.assertFalse(commit_allowed(1,1,1,False,True,True))
 def test_holder_key_without_live_challenge_cannot_commit(self):
  self.assertFalse(commit_allowed(0,0,0,False,True,False))
 def test_boolean_epoch_is_not_integer_alias(self):
  self.assertFalse(commit_allowed(True,1,1,True,True,False))
