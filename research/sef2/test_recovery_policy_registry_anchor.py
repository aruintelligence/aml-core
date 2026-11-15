import copy,pathlib,shutil,tempfile,unittest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from threshold_recovery import POLICY_SCHEMA,RecoveryAuthoritySigner
from recovery_policy_rotation import make_policy_rotation
from recovery_policy_registry import RecoveryPolicyRegistry
from recovery_anchor_quorum import (POLICY_SCHEMA as ANCHOR_POLICY_SCHEMA,
    RecoveryAnchorWitness,make_anchor_certificate,checkpoint_pin)
from recovery_policy_registry_anchor import (make_registry_anchor_payload,
    verify_registry_anchor,registry_checkpoint_pin,authority_set_fingerprint)

def policy(keys,name,schema=POLICY_SCHEMA):
 result={"schema":schema,"policy_id":name,"threshold":3,"max_faults":1,
  "authorities":{k:v.public_key().public_bytes_raw().hex() for k,v in keys.items()}}
 if schema==ANCHOR_POLICY_SCHEMA:
  result["administrative_domains"]={k:"operator-domain-"+k for k in keys}
 return result
def keyset(prefix): return {f"{prefix}-{i}":Ed25519PrivateKey.generate() for i in range(4)}

class RecoveryPolicyRegistryAnchorTests(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
  self.root=pathlib.Path(self.temp.name)
  self.old_keys=keyset("old"); self.new_keys=keyset("new")
  self.old=policy(self.old_keys,"recovery-v1"); self.new=policy(self.new_keys,"recovery-v2")
  self.old_signers={k:RecoveryAuthoritySigner(k,v,str(self.root/(k+".sqlite"))) for k,v in self.old_keys.items()}
  self.new_signers={k:RecoveryAuthoritySigner(k,v,str(self.root/(k+".sqlite"))) for k,v in self.new_keys.items()}
  self.registry_path=str(self.root/"registry.sqlite")
  self.registry=RecoveryPolicyRegistry(self.registry_path); self.registry.initialize(self.old)
  self.anchor_keys=keyset("anchor")
  self.anchor_policy=policy(self.anchor_keys,"anchor-council",ANCHOR_POLICY_SCHEMA)
  self.anchors={k:RecoveryAnchorWitness(k,v,str(self.root/(k+".anchor.sqlite"))) for k,v in self.anchor_keys.items()}
  self.first_state=self.registry.state()
  self.first_payload=make_registry_anchor_payload(self.first_state,1,"0"*64,self.anchor_policy)
  self.first_certificate=make_anchor_certificate(self.first_payload,self.anchor_policy,
      {k:self.anchors[k] for k in ("anchor-0","anchor-1","anchor-2")})
  self.first_pin=registry_checkpoint_pin(self.first_state)
 def rotate_registry(self):
  rotation=make_policy_rotation(self.old,self.new,2,
      {k:self.old_signers[k] for k in ("old-0","old-1","old-2")},
      {k:self.new_signers[k] for k in ("new-0","new-1","new-2")})
  self.assertEqual(self.registry.rotate(self.new,rotation),"ROTATED")
  state=self.registry.state()
  payload=make_registry_anchor_payload(state,2,self.first_pin,self.anchor_policy)
  cert=make_anchor_certificate(payload,self.anchor_policy,
      {k:self.anchors[k] for k in ("anchor-0","anchor-1","anchor-2")})
  return state,payload,cert
 def test_initial_registry_checkpoint_is_anchored_by_independent_quorum(self):
  self.assertTrue(verify_registry_anchor(self.first_state,self.first_payload,
      self.first_certificate,self.anchor_policy,1,"0"*64))
 def test_rotated_registry_generation_is_anchored(self):
  state,payload,cert=self.rotate_registry()
  self.assertTrue(verify_registry_anchor(state,payload,cert,self.anchor_policy,2,self.first_pin))
 def test_registry_snapshot_rollback_detected_against_new_anchor_certificate(self):
  snapshot=str(self.root/"registry-before-rotation.sqlite")
  shutil.copy2(self.registry_path,snapshot)
  state,payload,cert=self.rotate_registry()
  self.assertTrue(verify_registry_anchor(state,payload,cert,self.anchor_policy,2,self.first_pin))
  shutil.copy2(snapshot,self.registry_path)
  rolled_back=self.registry.state()
  self.assertFalse(verify_registry_anchor(rolled_back,payload,cert,self.anchor_policy,2,self.first_pin))
 def test_policy_substitution_changes_registry_authority_fingerprint(self):
  altered=copy.deepcopy(self.first_state)
  altered["policy"]={**self.new}
  altered["policy_sha256"]=__import__("threshold_recovery").policy_digest(self.new)
  self.assertNotEqual(authority_set_fingerprint(self.old),authority_set_fingerprint(self.new))
  self.assertFalse(verify_registry_anchor(altered,self.first_payload,self.first_certificate,
      self.anchor_policy,1,"0"*64))
 def test_registry_head_tampering_rejected(self):
  altered=dict(self.first_state); altered["head_sha256"]="f"*64
  self.assertFalse(verify_registry_anchor(altered,self.first_payload,self.first_certificate,
      self.anchor_policy,1,"0"*64))
 def test_registry_generation_rollback_rejected(self):
  altered=dict(self.first_state); altered["generation"]=0
  with self.assertRaises(ValueError): make_registry_anchor_payload(altered,0,"0"*64,self.anchor_policy)
 def test_anchor_certificate_signature_tampering_rejected(self):
  bad=copy.deepcopy(self.first_certificate); bad["approvals"][0]["signature"]="00"*64
  self.assertFalse(verify_registry_anchor(self.first_state,self.first_payload,bad,
      self.anchor_policy,1,"0"*64))
 def test_anchor_quorum_shortfall_rejected(self):
  bad=copy.deepcopy(self.first_certificate); bad["approvals"]=bad["approvals"][:2]
  self.assertFalse(verify_registry_anchor(self.first_state,self.first_payload,bad,
      self.anchor_policy,1,"0"*64))
 def test_wrong_previous_pin_cannot_advance_anchor_witness(self):
  bad=make_registry_anchor_payload(self.first_state,1,"1"*64,self.anchor_policy)
  with self.assertRaisesRegex(ValueError,"stale or forked"):
   self.anchors["anchor-3"].approve(bad,self.anchor_policy)
 def test_wrong_registry_identity_rejected(self):
  self.assertFalse(verify_registry_anchor(self.first_state,self.first_payload,
      self.first_certificate,self.anchor_policy,1,"0"*64,"another-registry"))
 def test_restart_keeps_anchor_quorum_sequence(self):
  self.anchors["anchor-0"]=RecoveryAnchorWitness("anchor-0",self.anchor_keys["anchor-0"],
      str(self.root/"anchor-0.anchor.sqlite"))
  advanced={**self.first_state,"generation":2,"head_sha256":"c"*64}
  with self.assertRaisesRegex(ValueError,"stale or forked"):
   self.anchors["anchor-0"].approve(make_registry_anchor_payload(advanced,2,"f"*64,
      self.anchor_policy),self.anchor_policy)

 def test_anchor_fingerprint_binds_quorum_and_fault_bound_not_only_member_keys(self):
  from threshold_recovery import validate_policy,policy_digest
  altered={**self.old,"max_faults":0}
  self.assertTrue(validate_policy(altered))
  self.assertEqual(altered["authorities"],self.old["authorities"])
  self.assertNotEqual(authority_set_fingerprint(self.old),authority_set_fingerprint(altered))
  changed_state={**self.first_state,"policy":altered,"policy_sha256":policy_digest(altered)}
  self.assertFalse(verify_registry_anchor(changed_state,self.first_payload,self.first_certificate,
      self.anchor_policy,1,"0"*64))
