import copy,pathlib,tempfile,unittest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from threshold_recovery import POLICY_SCHEMA,RecoveryAuthoritySigner
from recovery_target_registry import (RecoveryTargetRegistry,make_target_change,
 verify_target_change)

def policy(keys):
 return {"schema":POLICY_SCHEMA,"policy_id":"target-governance","threshold":3,"max_faults":1,
  "authorities":{n:k.public_key().public_bytes_raw().hex() for n,k in keys.items()},
  "administrative_domains":{n:"domain-"+n for n in keys}}

class RecoveryTargetRegistryTests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
  self.keys={f"r{i}":Ed25519PrivateKey.generate() for i in range(4)}
  self.policy=policy(self.keys)
  self.signers={n:RecoveryAuthoritySigner(n,k,pathlib.Path(self.tmp.name)/(n+".sqlite"))
    for n,k in self.keys.items()}
  self.quorum={n:self.signers[n] for n in ("r0","r1","r2")}
  self.path=pathlib.Path(self.tmp.name)/"targets.sqlite"
  self.registry=RecoveryTargetRegistry(self.path)
  self.registry.initialize(("authority-a","authority-b"))
  state=self.registry.state()
  self.change=make_target_change(state["targets"],2,state["head_sha256"],
    ["authority-c"],["authority-b"],self.policy,self.quorum)
 def test_quorum_authorized_target_change_updates_monotonic_registry(self):
  self.assertEqual(self.registry.apply(self.change,self.policy),"UPDATED")
  state=self.registry.state()
  self.assertEqual(state["generation"],2)
  self.assertEqual(state["targets"],["authority-a","authority-c"])
 def test_below_threshold_change_rejected(self):
  bad=copy.deepcopy(self.change); bad["approval"]["approvals"]=bad["approval"]["approvals"][:2]
  self.assertEqual(self.registry.apply(bad,self.policy),"INVALID_CHANGE")
 def test_removed_unknown_target_rejected_by_builder(self):
  state=self.registry.state()
  with self.assertRaises(ValueError):
   make_target_change(state["targets"],2,state["head_sha256"],[],["missing"],self.policy,self.quorum)
 def test_existing_target_cannot_be_readded(self):
  state=self.registry.state()
  with self.assertRaises(ValueError):
   make_target_change(state["targets"],2,state["head_sha256"],["authority-a"],[],self.policy,self.quorum)
 def test_empty_target_set_rejected(self):
  state=self.registry.state()
  with self.assertRaises(ValueError):
   make_target_change(state["targets"],2,state["head_sha256"],[],["authority-a","authority-b"],self.policy,self.quorum)
 def test_stale_change_rejected_after_update(self):
  self.registry.apply(self.change,self.policy)
  self.assertEqual(self.registry.apply(self.change,self.policy),"INVALID_CHANGE")
 def test_payload_target_substitution_rejected(self):
  bad=copy.deepcopy(self.change); bad["payload"]["next_targets"]=["authority-a","authority-d"]
  self.assertEqual(self.registry.apply(bad,self.policy),"INVALID_CHANGE")
 def test_policy_substitution_rejected(self):
  changed=copy.deepcopy(self.policy); changed["policy_id"]="other"
  self.assertEqual(self.registry.apply(self.change,changed),"INVALID_CHANGE")
 def test_generation_skip_rejected(self):
  bad=copy.deepcopy(self.change); bad["payload"]["generation"]=3
  self.assertEqual(self.registry.apply(bad,self.policy),"INVALID_CHANGE")
 def test_storage_failure_rolls_back_target_state(self):
  import sqlite3
  with sqlite3.connect(self.path) as con:
   con.execute("""CREATE TRIGGER reject_target_event BEFORE INSERT ON target_events
    BEGIN SELECT RAISE(ABORT,'injected target event failure'); END""")
  before=self.registry.state()
  self.assertEqual(self.registry.apply(self.change,self.policy),"STORE_OR_STATE_ERROR")
  self.assertEqual(self.registry.state(),before)
