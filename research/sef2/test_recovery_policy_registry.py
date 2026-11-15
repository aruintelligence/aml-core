import copy,concurrent.futures,pathlib,tempfile,unittest,sqlite3
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from signed_receipt import canonical
from threshold_recovery import POLICY_SCHEMA,RecoveryAuthoritySigner,make_approval_bundle,policy_digest
from recovery_policy_rotation import make_policy_rotation,ROTATION_SCHEMA
from recovery_policy_registry import RecoveryPolicyRegistry

def mkpolicy(keys,name):
 return {"schema":POLICY_SCHEMA,"policy_id":name,"threshold":3,"max_faults":1,
  "authorities":{k:v.public_key().public_bytes_raw().hex() for k,v in keys.items()},
  "administrative_domains":{k:name+"-domain-"+k for k in keys}}
def keys(prefix): return {f"{prefix}-{i}":Ed25519PrivateKey.generate() for i in range(4)}
def unsafe_rotation(old,new,g,old_keys,new_keys):
 # Deliberately models a fully equivocating outgoing council to test that the
 # registry still commits at most one serialized successor state.
 previous=policy_digest(old)
 payload={"schema":ROTATION_SCHEMA,"generation":g,"witness_id":"recovery-policy",
  "previous_state_sha256":previous,"previous_policy_sha256":previous,
  "next_policy_sha256":policy_digest(new)}
 return {"schema":ROTATION_SCHEMA,"payload":payload,
  "outgoing_approval":make_approval_bundle(payload,old,old_keys),
  "incoming_acceptance":make_approval_bundle(payload,new,new_keys)}

class RecoveryPolicyRegistryTests(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
  self.path=str(pathlib.Path(self.temp.name)/"policy.sqlite")
  self.old_keys=keys("old"); self.new_keys=keys("new"); self.alt_keys=keys("alt")
  self.old=mkpolicy(self.old_keys,"council-v1")
  self.new=mkpolicy(self.new_keys,"council-v2")
  self.alt=mkpolicy(self.alt_keys,"council-alt")
  self.old_signers={k:RecoveryAuthoritySigner(k,v,str(pathlib.Path(self.temp.name)/(k+".sqlite"))) for k,v in self.old_keys.items()}
  self.new_signers={k:RecoveryAuthoritySigner(k,v,str(pathlib.Path(self.temp.name)/(k+".sqlite"))) for k,v in self.new_keys.items()}
  self.registry=RecoveryPolicyRegistry(self.path); self.registry.initialize(self.old)
  self.rotation=make_policy_rotation(self.old,self.new,2,
   {k:self.old_signers[k] for k in ("old-0","old-1","old-2")},
   {k:self.new_signers[k] for k in ("new-0","new-1","new-2")})
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
 def test_competing_equivocating_certificates_only_one_state_transition_wins(self):
  left=unsafe_rotation(self.old,self.new,2,self.old_keys,self.new_keys)
  right=unsafe_rotation(self.old,self.alt,2,self.old_keys,self.alt_keys)
  with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
   results=list(pool.map(lambda pair:self.registry.rotate(*pair),[(self.new,left),(self.alt,right)]))
  self.assertEqual(results.count("ROTATED"),1)
  self.assertEqual(results.count("INVALID_ROTATION"),1)
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
  self.assertEqual(self.registry.state(),before)
  self.assertTrue(self.registry.verify_history())
 def test_corrupted_state_fails_closed(self):
  with sqlite3.connect(self.path) as con:
   con.execute("UPDATE recovery_policy_state SET current_policy_sha256=? WHERE singleton=1",("0"*64,))
  with self.assertRaisesRegex(ValueError,"corrupt"): self.registry.state()
  self.assertEqual(self.registry.rotate(self.new,self.rotation),"CORRUPT_STATE")
  with self.assertRaisesRegex(ValueError,"corrupt"): self.registry.initialize(self.old)
 def test_history_event_tampering_detected(self):
  self.registry.rotate(self.new,self.rotation)
  with sqlite3.connect(self.path) as con:
   con.execute("UPDATE recovery_policy_events SET next_policy_json=? WHERE generation=2",('"corrupted"',))
  self.assertFalse(self.registry.verify_history())
 def test_uninitialized_registry_fails_closed(self):
  path=str(pathlib.Path(self.temp.name)/"empty.sqlite")
  other=RecoveryPolicyRegistry(path)
  self.assertEqual(other.rotate(self.new,self.rotation),"UNINITIALIZED")
  self.assertFalse(other.verify_history())
 def test_initialization_is_idempotent_but_cannot_replace_policy(self):
  self.assertEqual(self.registry.initialize(self.old),"ALREADY_INITIALIZED")
  with self.assertRaisesRegex(ValueError,"already initialized"):
   self.registry.initialize(self.new)


class AnchoredRecoveryPolicyRegistryTests(unittest.TestCase):
 def setUp(self):
  from threshold_recovery import MemoryRecoveryHeadAnchor
  self.temp=tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
  self.path=str(pathlib.Path(self.temp.name)/"anchored-policy.sqlite")
  self.anchor=MemoryRecoveryHeadAnchor("policy-anchor")
  self.old_keys=keys("anchor-old"); self.new_keys=keys("anchor-new")
  self.old=mkpolicy(self.old_keys,"anchored-v1"); self.new=mkpolicy(self.new_keys,"anchored-v2")
  self.old_signers={k:RecoveryAuthoritySigner(k,v,str(pathlib.Path(self.temp.name)/(k+".sqlite"))) for k,v in self.old_keys.items()}
  self.new_signers={k:RecoveryAuthoritySigner(k,v,str(pathlib.Path(self.temp.name)/(k+".sqlite"))) for k,v in self.new_keys.items()}
  self.registry=RecoveryPolicyRegistry(self.path,self.anchor); self.registry.initialize(self.old)
  self.rotation=make_policy_rotation(self.old,self.new,2,
   {k:self.old_signers[k] for k in ("anchor-old-0","anchor-old-1","anchor-old-2")},
   {k:self.new_signers[k] for k in ("anchor-new-0","anchor-new-1","anchor-new-2")})
 def test_rotation_updates_independent_anchor(self):
  self.assertEqual(self.registry.rotate(self.new,self.rotation),"ROTATED")
  self.assertEqual(self.anchor.read_head(),self.registry.state()["head_sha256"])
 def test_local_database_rollback_is_detected_against_anchor(self):
  import shutil
  snapshot=str(pathlib.Path(self.temp.name)/"before.sqlite"); shutil.copy2(self.path,snapshot)
  self.assertEqual(self.registry.rotate(self.new,self.rotation),"ROTATED")
  shutil.copy2(snapshot,self.path)
  with self.assertRaisesRegex(ValueError,"rolled-back"):
   self.registry.state()
  self.assertFalse(self.registry.verify_history())
 def test_anchor_update_failure_strands_local_commit_fail_closed(self):
  class Refuse:
   def __init__(inner): inner.anchor_id="refuse"; inner.head="0"*64
   def read_head(inner): return inner.head
   def compare_and_set(inner,old,new): return False
  anchor=Refuse()
  path=str(pathlib.Path(self.temp.name)/"refuse.sqlite")
  registry=RecoveryPolicyRegistry(path,anchor); registry.initialize(self.old)
  self.assertEqual(registry.rotate(self.new,self.rotation),"ANCHOR_UPDATE_FAILED")
  with self.assertRaisesRegex(ValueError,"rolled-back"):
   registry.state()
 def test_reconcile_completes_committed_rotation_after_anchor_failure(self):
  class FailOnce:
   def __init__(inner): inner.anchor_id="once"; inner.head="0"*64; inner.fail=True
   def read_head(inner): return inner.head
   def compare_and_set(inner,old,new):
    if inner.fail: inner.fail=False; return False
    if inner.head!=old: return False
    inner.head=new; return True
  anchor=FailOnce()
  path=str(pathlib.Path(self.temp.name)/"once.sqlite")
  registry=RecoveryPolicyRegistry(path,anchor); registry.initialize(self.old)
  self.assertEqual(registry.rotate(self.new,self.rotation),"ANCHOR_UPDATE_FAILED")
  head=registry.reconcile_anchor()
  self.assertEqual(anchor.read_head(),head)
  self.assertEqual(registry.state()["head_sha256"],head)
 def test_reconcile_refuses_anchor_on_unrelated_history(self):
  self.assertTrue(self.anchor.compare_and_set("0"*64,"f"*64))
  with self.assertRaisesRegex(RuntimeError,"EXPECTED_PREDECESSOR_MISMATCH"):
   self.registry.reconcile_anchor()
 def test_unavailable_anchor_blocks_rotation_before_mutation(self):
  class Down:
   anchor_id="down"
   def read_head(self): raise OSError("offline")
   def compare_and_set(self,*args): raise OSError("offline")
  path=str(pathlib.Path(self.temp.name)/"down.sqlite")
  registry=RecoveryPolicyRegistry(path,Down()); registry.initialize(self.old)
  before=registry._local_state()
  self.assertEqual(registry.rotate(self.new,self.rotation),"ANCHOR_UNAVAILABLE")
  self.assertEqual(registry._local_state(),before)

class EmergencyRecoveryPolicyRegistryTests(unittest.TestCase):
 def setUp(self):
  from recovery_emergency_rotation import make_emergency_rotation
  self.temp=tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
  self.path=str(pathlib.Path(self.temp.name)/"emergency-policy.sqlite")
  self.old_keys=keys("e-old"); self.new_keys=keys("e-new")
  self.old=mkpolicy(self.old_keys,"emergency-recovery-v1")
  self.new=mkpolicy(self.new_keys,"emergency-recovery-v2")
  self.new_signers={k:RecoveryAuthoritySigner(k,v,str(pathlib.Path(self.temp.name)/(k+".sqlite")))
   for k,v in self.new_keys.items()}
  self.guardian_keys={f"guardian-{i}":Ed25519PrivateKey.generate() for i in range(5)}
  self.guardians={"schema":POLICY_SCHEMA,"policy_id":"break-glass-v1","threshold":4,
   "max_faults":1,"authorities":{k:v.public_key().public_bytes_raw().hex() for k,v in self.guardian_keys.items()},
   "administrative_domains":{k:"break-glass-domain-"+k for k in self.guardian_keys}}
  self.guardian_signers={k:RecoveryAuthoritySigner(k,v,str(pathlib.Path(self.temp.name)/(k+".sqlite")))
   for k,v in self.guardian_keys.items()}
  self.registry=RecoveryPolicyRegistry(self.path); self.registry.initialize(self.old)
  head=self.registry.state()["head_sha256"]
  self.rotation=make_emergency_rotation(self.old,self.new,self.guardians,2,head,"b"*64,
   "QUORUM_LOSS",{k:self.guardian_signers[k] for k in list(self.guardian_signers)[:4]},
   {k:self.new_signers[k] for k in list(self.new_signers)[:3]})
 def test_emergency_rotation_persists_in_same_policy_history(self):
  self.assertEqual(self.registry.emergency_rotate(self.new,self.guardians,self.rotation),"EMERGENCY_ROTATED")
  state=self.registry.state()
  self.assertEqual(state["generation"],2); self.assertEqual(state["policy"],self.new)
  self.assertTrue(self.registry.verify_history())
 def test_emergency_rotation_survives_restart_and_reverifies(self):
  self.assertEqual(self.registry.emergency_rotate(self.new,self.guardians,self.rotation),"EMERGENCY_ROTATED")
  restarted=RecoveryPolicyRegistry(self.path)
  self.assertEqual(restarted.state()["policy"],self.new)
  self.assertTrue(restarted.verify_history())
 def test_emergency_rotation_replay_is_rejected(self):
  self.registry.emergency_rotate(self.new,self.guardians,self.rotation)
  self.assertEqual(self.registry.emergency_rotate(self.new,self.guardians,self.rotation),"INVALID_EMERGENCY_ROTATION")
 def test_emergency_incident_tamper_does_not_mutate_registry(self):
  bad=copy.deepcopy(self.rotation); bad["payload"]["incident_sha256"]="f"*64
  before=self.registry.state()
  self.assertEqual(self.registry.emergency_rotate(self.new,self.guardians,bad),"INVALID_EMERGENCY_ROTATION")
  self.assertEqual(self.registry.state(),before)
 def test_normal_rotation_can_follow_emergency_rotation(self):
  self.assertEqual(self.registry.emergency_rotate(self.new,self.guardians,self.rotation),"EMERGENCY_ROTATED")
  third_keys=keys("e-third"); third=mkpolicy(third_keys,"emergency-recovery-v3")
  third_signers={k:RecoveryAuthoritySigner(k,v,str(pathlib.Path(self.temp.name)/(k+".sqlite")))
   for k,v in third_keys.items()}
  normal=make_policy_rotation(self.new,third,3,
   {k:self.new_signers[k] for k in list(self.new_signers)[:3]},
   {k:third_signers[k] for k in list(third_signers)[:3]})
  self.assertEqual(self.registry.rotate(third,normal),"ROTATED")
  self.assertEqual(self.registry.state()["generation"],3)
  self.assertEqual(self.registry.state()["policy"],third)
  self.assertTrue(self.registry.verify_history())
 def test_emergency_storage_failure_rolls_back_state(self):
  with sqlite3.connect(self.path) as con:
   con.execute("""CREATE TRIGGER reject_emergency_event BEFORE INSERT ON recovery_policy_emergency_events
    BEGIN SELECT RAISE(ABORT,'injected emergency event failure'); END""")
  before=self.registry.state()
  self.assertEqual(self.registry.emergency_rotate(self.new,self.guardians,self.rotation),"STORE_OR_STATE_ERROR")
  self.assertEqual(self.registry.state(),before)
 def test_anchored_emergency_rotation_detects_local_rollback(self):
  import shutil
  from threshold_recovery import MemoryRecoveryHeadAnchor
  anchor=MemoryRecoveryHeadAnchor("emergency-policy-anchor")
  path=str(pathlib.Path(self.temp.name)/"anchored-emergency.sqlite")
  registry=RecoveryPolicyRegistry(path,anchor); registry.initialize(self.old)
  from recovery_emergency_rotation import make_emergency_rotation
  rotation=self.rotation
  snapshot=str(pathlib.Path(self.temp.name)/"emergency-before.sqlite"); shutil.copy2(path,snapshot)
  self.assertEqual(registry.emergency_rotate(self.new,self.guardians,rotation),"EMERGENCY_ROTATED")
  shutil.copy2(snapshot,path)
  with self.assertRaisesRegex(ValueError,"rolled-back"):
   registry.state()
