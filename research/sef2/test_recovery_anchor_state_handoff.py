import copy,pathlib,tempfile,unittest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from threshold_recovery import RecoveryAuthoritySigner
from recovery_anchor_quorum import (POLICY_SCHEMA,RecoveryAnchorWitness,
 make_anchor_payload)
from recovery_anchor_policy_rotation import make_anchor_policy_rotation
from recovery_anchor_state_handoff import (make_anchor_state_handoff,
 verify_anchor_state_handoff,bootstrap_successor_anchor)

def policy(keys,name):
 return {"schema":POLICY_SCHEMA,"policy_id":name,"threshold":3,"max_faults":1,
  "authorities":{n:k.public_key().public_bytes_raw().hex() for n,k in keys.items()},
  "administrative_domains":{n:name+"-"+n for n in keys}}

class RecoveryAnchorStateHandoffTests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
  root=pathlib.Path(self.tmp.name)
  self.old_keys={f"old-{i}":Ed25519PrivateKey.generate() for i in range(4)}
  self.new_keys={f"new-{i}":Ed25519PrivateKey.generate() for i in range(4)}
  self.old=policy(self.old_keys,"anchor-v1"); self.new=policy(self.new_keys,"anchor-v2")
  self.old_signers={n:RecoveryAuthoritySigner(n,k,root/(n+"-handoff.sqlite")) for n,k in self.old_keys.items()}
  self.new_signers={n:RecoveryAuthoritySigner(n,k,root/(n+"-handoff.sqlite")) for n,k in self.new_keys.items()}
  self.old_q={n:self.old_signers[n] for n in ("old-0","old-1","old-2")}
  self.new_q={n:self.new_signers[n] for n in ("new-0","new-1","new-2")}
  self.rotation=make_anchor_policy_rotation(self.old,self.new,2,"a"*64,self.old_q,self.new_q)
  self.targets=("authority-a","authority-b")
  self.snapshot={"authority-a":{"sequence":7,"pin_sha256":"b"*64},
                 "authority-b":{"sequence":3,"pin_sha256":"c"*64}}
  self.handoff=make_anchor_state_handoff(self.old,self.new,self.rotation,2,"a"*64,
    self.targets,self.snapshot,self.old_q,self.new_q)
 def test_dual_council_state_handoff_verifies(self):
  self.assertTrue(verify_anchor_state_handoff(self.old,self.new,self.rotation,
    self.handoff,2,"a"*64,self.targets))
 def test_snapshot_tampering_rejected(self):
  h=copy.deepcopy(self.handoff); h["payload"]["state_snapshot"]["authority-a"]["pin_sha256"]="f"*64
  self.assertFalse(verify_anchor_state_handoff(self.old,self.new,self.rotation,h,2,"a"*64,self.targets))
 def test_outgoing_state_quorum_shortfall_rejected(self):
  h=copy.deepcopy(self.handoff); h["outgoing_state_approval"]["approvals"]=h["outgoing_state_approval"]["approvals"][:2]
  self.assertFalse(verify_anchor_state_handoff(self.old,self.new,self.rotation,h,2,"a"*64,self.targets))
 def test_incoming_state_quorum_shortfall_rejected(self):
  h=copy.deepcopy(self.handoff); h["incoming_state_acceptance"]["approvals"]=h["incoming_state_acceptance"]["approvals"][:2]
  self.assertFalse(verify_anchor_state_handoff(self.old,self.new,self.rotation,h,2,"a"*64))
 def test_rotation_substitution_rejected(self):
  r=copy.deepcopy(self.rotation); r["payload"]["previous_anchor_pin"]="f"*64
  self.assertFalse(verify_anchor_state_handoff(self.old,self.new,r,self.handoff,2,"a"*64,self.targets))
 def test_successor_bootstrap_continues_exact_monotonic_sequence(self):
  witness=RecoveryAnchorWitness("new-0",self.new_keys["new-0"],
    pathlib.Path(self.tmp.name)/"new-0-anchor.sqlite")
  self.assertEqual(bootstrap_successor_anchor(witness,self.old,self.new,self.rotation,
    self.handoff,2,"a"*64,self.targets),"BOOTSTRAPPED")
  checkpoint={"schema":"AML-SEF2-RECOVERY-LEDGER-CHECKPOINT-V1",
   "authority_id":"authority-a","authority_key_sha256":"d"*64,
   "sequence":8,"head_hash":"e"*64}
  payload=make_anchor_payload(checkpoint,8,"b"*64,self.new)
  self.assertEqual(len(witness.approve(payload,self.new)),128)
 def test_successor_cannot_restart_target_from_genesis(self):
  witness=RecoveryAnchorWitness("new-0",self.new_keys["new-0"],
    pathlib.Path(self.tmp.name)/"new-0-anchor-genesis.sqlite")
  bootstrap_successor_anchor(witness,self.old,self.new,self.rotation,self.handoff,2,"a"*64,self.targets)
  checkpoint={"schema":"AML-SEF2-RECOVERY-LEDGER-CHECKPOINT-V1",
   "authority_id":"authority-a","authority_key_sha256":"d"*64,
   "sequence":1,"head_hash":"e"*64}
  with self.assertRaisesRegex(ValueError,"stale or forked"):
   witness.approve(make_anchor_payload(checkpoint,1,"0"*64,self.new),self.new)
 def test_wrong_successor_key_rejected(self):
  witness=RecoveryAnchorWitness("new-0",Ed25519PrivateKey.generate(),
    pathlib.Path(self.tmp.name)/"wrong.sqlite")
  with self.assertRaisesRegex(ValueError,"identity/key mismatch"):
   bootstrap_successor_anchor(witness,self.old,self.new,self.rotation,self.handoff,2,"a"*64,self.targets)
 def test_nonempty_successor_database_rejected(self):
  witness=RecoveryAnchorWitness("new-0",self.new_keys["new-0"],
    pathlib.Path(self.tmp.name)/"used.sqlite")
  checkpoint={"schema":"AML-SEF2-RECOVERY-LEDGER-CHECKPOINT-V1",
   "authority_id":"other","authority_key_sha256":"d"*64,"sequence":1,"head_hash":"e"*64}
  witness.approve(make_anchor_payload(checkpoint,1,"0"*64,self.new),self.new)
  with self.assertRaisesRegex(ValueError,"already contains state"):
   bootstrap_successor_anchor(witness,self.old,self.new,self.rotation,self.handoff,2,"a"*64)

 def test_snapshot_omission_is_rejected_against_expected_target_set(self):
  incomplete={"authority-a":dict(self.snapshot["authority-a"])}
  with self.assertRaisesRegex(ValueError,"incomplete"):
   make_anchor_state_handoff(self.old,self.new,self.rotation,2,"a"*64,
    self.targets,incomplete,self.old_q,self.new_q)
 def test_verifier_rejects_external_target_set_with_missing_or_extra_target(self):
  self.assertFalse(verify_anchor_state_handoff(self.old,self.new,self.rotation,
   self.handoff,2,"a"*64,("authority-a",)))
  self.assertFalse(verify_anchor_state_handoff(self.old,self.new,self.rotation,
   self.handoff,2,"a"*64,("authority-a","authority-b","authority-c")))
 def test_bootstrap_rejects_different_external_target_manifest(self):
  witness=RecoveryAnchorWitness("new-0",self.new_keys["new-0"],
    pathlib.Path(self.tmp.name)/"target-mismatch.sqlite")
  with self.assertRaisesRegex(ValueError,"invalid anchor state handoff"):
   bootstrap_successor_anchor(witness,self.old,self.new,self.rotation,
    self.handoff,2,"a"*64,("authority-a",))
