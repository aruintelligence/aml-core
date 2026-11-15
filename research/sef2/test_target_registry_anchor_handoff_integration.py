import pathlib,tempfile,unittest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from threshold_recovery import POLICY_SCHEMA as RECOVERY_POLICY_SCHEMA,RecoveryAuthoritySigner
from recovery_target_registry import RecoveryTargetRegistry,make_target_change
from recovery_anchor_quorum import POLICY_SCHEMA as ANCHOR_POLICY_SCHEMA
from recovery_anchor_policy_rotation import make_anchor_policy_rotation
from recovery_anchor_state_handoff import make_anchor_state_handoff,verify_anchor_state_handoff

def recovery_policy(keys):
 return {"schema":RECOVERY_POLICY_SCHEMA,"policy_id":"target-governance-e2e",
  "threshold":3,"max_faults":1,
  "authorities":{n:k.public_key().public_bytes_raw().hex() for n,k in keys.items()},
  "administrative_domains":{n:"recovery-domain-"+n for n in keys}}
def anchor_policy(keys,name):
 return {"schema":ANCHOR_POLICY_SCHEMA,"policy_id":name,"threshold":3,"max_faults":1,
  "authorities":{n:k.public_key().public_bytes_raw().hex() for n,k in keys.items()},
  "administrative_domains":{n:name+"-"+n for n in keys}}

class TargetRegistryAnchorHandoffIntegrationTests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
  root=pathlib.Path(self.tmp.name)
  self.recovery_keys={f"r{i}":Ed25519PrivateKey.generate() for i in range(4)}
  self.recovery_policy=recovery_policy(self.recovery_keys)
  self.recovery_signers={n:RecoveryAuthoritySigner(n,k,root/(n+"-recovery.sqlite"))
    for n,k in self.recovery_keys.items()}
  self.recovery_quorum={n:self.recovery_signers[n] for n in ("r0","r1","r2")}
  self.target_registry=RecoveryTargetRegistry(root/"targets.sqlite")
  self.target_registry.initialize(("authority-a","authority-b"))
  self.old_anchor_keys={f"old-{i}":Ed25519PrivateKey.generate() for i in range(4)}
  self.new_anchor_keys={f"new-{i}":Ed25519PrivateKey.generate() for i in range(4)}
  self.old_policy=anchor_policy(self.old_anchor_keys,"anchor-old")
  self.new_policy=anchor_policy(self.new_anchor_keys,"anchor-new")
  self.old_signers={n:RecoveryAuthoritySigner(n,k,root/(n+"-anchor.sqlite"))
    for n,k in self.old_anchor_keys.items()}
  self.new_signers={n:RecoveryAuthoritySigner(n,k,root/(n+"-anchor.sqlite"))
    for n,k in self.new_anchor_keys.items()}
  self.old_q={n:self.old_signers[n] for n in ("old-0","old-1","old-2")}
  self.new_q={n:self.new_signers[n] for n in ("new-0","new-1","new-2")}
  self.rotation=make_anchor_policy_rotation(self.old_policy,self.new_policy,2,"a"*64,
    self.old_q,self.new_q)

 def snapshot_for(self,targets):
  return {target:{"sequence":1,"pin_sha256":("b" if i==0 else "c")*64}
    for i,target in enumerate(targets)}

 def test_handoff_uses_current_target_registry_membership(self):
  state=self.target_registry.state()
  targets=tuple(state["targets"]); snapshot=self.snapshot_for(targets)
  handoff=make_anchor_state_handoff(self.old_policy,self.new_policy,self.rotation,2,"a"*64,
    targets,snapshot,self.old_q,self.new_q)
  self.assertTrue(verify_anchor_state_handoff(self.old_policy,self.new_policy,self.rotation,
    handoff,2,"a"*64,tuple(self.target_registry.state()["targets"])))

 def test_quorum_authorized_target_change_invalidates_stale_handoff_membership(self):
  before=self.target_registry.state()
  stale_targets=tuple(before["targets"]); stale_snapshot=self.snapshot_for(stale_targets)
  stale_handoff=make_anchor_state_handoff(self.old_policy,self.new_policy,self.rotation,2,"a"*64,
    stale_targets,stale_snapshot,self.old_q,self.new_q)
  change=make_target_change(before["targets"],before["generation"]+1,before["head_sha256"],
    ["authority-c"],["authority-b"],self.recovery_policy,self.recovery_quorum)
  self.assertEqual(self.target_registry.apply(change,self.recovery_policy),"UPDATED")
  current_targets=tuple(self.target_registry.state()["targets"])
  self.assertEqual(current_targets,("authority-a","authority-c"))
  self.assertFalse(verify_anchor_state_handoff(self.old_policy,self.new_policy,self.rotation,
    stale_handoff,2,"a"*64,current_targets))

 def test_new_handoff_after_target_change_must_cover_new_member_and_drop_removed_member(self):
  before=self.target_registry.state()
  change=make_target_change(before["targets"],2,before["head_sha256"],
    ["authority-c"],["authority-b"],self.recovery_policy,self.recovery_quorum)
  self.assertEqual(self.target_registry.apply(change,self.recovery_policy),"UPDATED")
  targets=tuple(self.target_registry.state()["targets"])
  snapshot=self.snapshot_for(targets)
  handoff=make_anchor_state_handoff(self.old_policy,self.new_policy,self.rotation,2,"a"*64,
    targets,snapshot,self.old_q,self.new_q)
  self.assertTrue(verify_anchor_state_handoff(self.old_policy,self.new_policy,self.rotation,
    handoff,2,"a"*64,targets))
  self.assertIn("authority-c",handoff["payload"]["state_snapshot"])
  self.assertNotIn("authority-b",handoff["payload"]["state_snapshot"])

 def test_unapproved_local_target_registry_edit_cannot_validate_stale_handoff(self):
  import sqlite3,json
  state=self.target_registry.state()
  targets=tuple(state["targets"]); handoff=make_anchor_state_handoff(
    self.old_policy,self.new_policy,self.rotation,2,"a"*64,targets,self.snapshot_for(targets),
    self.old_q,self.new_q)
  with sqlite3.connect(self.target_registry.path) as con:
   con.execute("UPDATE target_state SET targets_json=? WHERE singleton=1",
     (json.dumps(["authority-a","authority-x"],separators=(",",":")),))
  tampered_targets=tuple(self.target_registry.state()["targets"])
  self.assertFalse(verify_anchor_state_handoff(self.old_policy,self.new_policy,self.rotation,
    handoff,2,"a"*64,tampered_targets))
