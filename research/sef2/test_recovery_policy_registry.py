import copy,concurrent.futures,pathlib,tempfile,unittest,sqlite3
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from threshold_recovery import POLICY_SCHEMA
from recovery_policy_rotation import make_policy_rotation
from recovery_policy_registry import RecoveryPolicyRegistry

def mkpolicy(keys,name):
 return {"schema":POLICY_SCHEMA,"policy_id":name,"threshold":3,"max_faults":1,
  "authorities":{k:v.public_key().public_bytes_raw().hex() for k,v in keys.items()}}
def mkkeys(prefix): return {f"{prefix}-{i}":Ed25519PrivateKey.generate() for i in range(4)}
def make_rotation(old,new,g,oldkeys,newkeys):
 return make_policy_rotation(old,new,g,
  {k:oldkeys[k] for k in list(oldkeys)[:3]},
  {k:newkeys[k] for k in list(newkeys)[:3]})

class RecoveryPolicyRegistryTests(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
  self.path=str(pathlib.Path(self.temp.name)/"policy.sqlite")
  self.oldkeys=mkkeys("old"); self.newkeys=mkkeys("new"); self.altkeys=mkkeys("alt")
  self.old=mkpolicy(self.oldkeys,"council-v1"); self.new=mkpolicy(self.newkeys,"council-v2")
  self.alt=mkpolicy(self.altkeys,"council-alt")
  self.registry=RecoveryPolicyRegistry(self.path); self.registry.initialize(self.old)
  self.rotation=make_rotation(self.old,self.new,2,self.oldkeys,self.newkeys)
 def test_dual_consent_rotation_persists_new_policy(self):
  self.assertEqual(self.registry.rotate(self.new,self.rotation),"ROTATED")
  state=self.registry.state()
  self.assertEqual(state["generation"],2); self.assertEqual(state["policy"],self.new)
  self.assertTrue(self.registry.verify_history())
 def test_rotation_survives_registry_restart(self):
  self.registry.rotate(self.new,self.rotation)
  restarted=RecoveryPolicyRegistry(self.path)
  self.assertEqual(restarted.state()["policy"],self.new); self.assertTrue(restarted.verify_history())
 def test_replay_of_old_rotation_rejected(self):
  self.registry.rotate(self.new,self.rotation)
  self.assertEqual(self.registry.rotate(self.new,self.rotation),"INVALID_ROTATION")
 def test_old_policy_cannot_be_restored_with_stale_rotation(self):
  self.registry.rotate(self.new,self.rotation)
  self.assertEqual(self.registry.rotate(self.old,self.rotation),"INVALID_ROTATION")
 def test_competing_policy_rotations_only_one_wins(self):
  left=self.rotation
  right=make_rotation(self.old,self.alt,2,self.oldkeys,self.altkeys)
  with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
   results=list(pool.map(lambda pair:self.registry.rotate(*pair),[(self.new,left),(self.alt,right)]))
  self.assertEqual(results.count("ROTATED"),1); self.assertEqual(results.count("INVALID_ROTATION"),1)
  self.assertTrue(self.registry.verify_history())
 def test_invalid_rotation_does_not_mutate_registry(self):
  bad=copy.deepcopy(self.rotation); bad["outgoing_approval"]["approvals"]=bad["outgoing_approval"]["approvals"][:2]
  before=self.registry.state()
  self.assertEqual(self.registry.rotate(self.new,bad),"INVALID_ROTATION")
  self.assertEqual(self.registry.state(),before)
 def test_storage_failure_rolls_back_policy_and_history(self):
  with sqlite3.connect(self.path) as con:
   con.execute("""CREATE TRIGGER reject_policy_event BEFORE INSERT ON recovery_policy_events
    BEGIN SELECT RAISE(ABORT,'injected event failure'); END""")
  before=self.registry.state()
  self.assertEqual(self.registry.rotate(self.new,self.rotation),"STORE_OR_STATE_ERROR")
  self.assertEqual(self.registry.state(),before); self.assertTrue(self.registry.verify_history())
 def test_corrupted_state_fails_closed(self):
  with sqlite3.connect(self.path) as con: con.execute("UPDATE recovery_policy_state SET policy_sha256=? WHERE singleton=1",("0"*64,))
  with self.assertRaisesRegex(ValueError,"corrupt"): self.registry.state()
  self.assertEqual(self.registry.rotate(self.new,self.rotation),"CORRUPT_STATE")
 def test_history_event_tampering_detected(self):
  self.registry.rotate(self.new,self.rotation)
  with sqlite3.connect(self.path) as con: con.execute("UPDATE recovery_policy_events SET next_policy_sha256=? WHERE generation=2",("f"*64,))
  self.assertFalse(self.registry.verify_history())
 def test_uninitialized_registry_fails_closed(self):
  path=str(pathlib.Path(self.temp.name)/"empty.sqlite"); other=RecoveryPolicyRegistry(path)
  self.assertEqual(other.rotate(self.new,self.rotation),"UNINITIALIZED")
  self.assertFalse(other.verify_history())
