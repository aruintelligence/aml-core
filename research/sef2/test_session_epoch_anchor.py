import pathlib,shutil,tempfile,unittest
from session_epoch_anchor import SessionEpochAnchor

class SessionEpochAnchorTests(unittest.TestCase):
 def setUp(self):
  t=tempfile.TemporaryDirectory(); self.addCleanup(t.cleanup); self.root=pathlib.Path(t.name)
  self.anchor=SessionEpochAnchor(self.root/"anchor.sqlite"); self.anchor.initialize("broker-a",0)
 def test_monotonic_compare_and_set(self):
  self.assertTrue(self.anchor.compare_and_set("broker-a",0,1))
  self.assertEqual(self.anchor.read_epoch("broker-a"),1)
  self.assertFalse(self.anchor.compare_and_set("broker-a",0,1))
  self.assertFalse(self.anchor.compare_and_set("broker-a",1,3))
 def test_restart_retains_epoch(self):
  self.anchor.compare_and_set("broker-a",0,1)
  self.assertEqual(SessionEpochAnchor(self.root/"anchor.sqlite").read_epoch("broker-a"),1)
 def test_conflicting_initialization_rejected(self):
  with self.assertRaises(ValueError): self.anchor.initialize("broker-a",1)

 def test_remote_client_treats_explicit_missing_as_uninitialized_not_denied(self):
  from session_epoch_anchor import RemoteSessionEpochAnchor
  class Fake(RemoteSessionEpochAnchor):
   def _call(self,payload): return {"status":"MISSING"}
  with self.assertRaises(ValueError): Fake("unused").read_epoch("new-audience")
