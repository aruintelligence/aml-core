import unittest
from execution_rollback_model import explore

class ExecutionRollbackModelTests(unittest.TestCase):
 def test_independent_consumption_prevents_double_execution_within_bound(self):
  self.assertEqual(explore(depth=10,broken=False),[])
 def test_local_only_consumption_exposes_rollback_double_execution(self):
  paths=explore(depth=6,broken=True)
  self.assertTrue(paths)
  path=paths[0]
  self.assertIn("rollback_broker",path)
  self.assertGreaterEqual(path.count("execute"),2)
 def test_counterexample_is_reproducible_and_short(self):
  path=explore(depth=6,broken=True)[0]
  self.assertLessEqual(len(path),6)
