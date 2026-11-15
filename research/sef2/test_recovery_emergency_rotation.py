import copy,pathlib,tempfile,unittest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from threshold_recovery import POLICY_SCHEMA,RecoveryAuthoritySigner
from recovery_emergency_rotation import make_emergency_rotation,verify_emergency_rotation

def policy(keys,name,threshold,max_faults):
 return {"schema":POLICY_SCHEMA,"policy_id":name,"threshold":threshold,"max_faults":max_faults,
  "authorities":{k:v.public_key().public_bytes_raw().hex() for k,v in keys.items()},
  "administrative_domains":{k:name+"-domain-"+k for k in keys}}

class EmergencyRecoveryRotationTests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
  self.old_keys={f"old-{i}":Ed25519PrivateKey.generate() for i in range(4)}
  self.new_keys={f"new-{i}":Ed25519PrivateKey.generate() for i in range(4)}
  self.guardian_keys={f"guardian-{i}":Ed25519PrivateKey.generate() for i in range(5)}
  self.old=policy(self.old_keys,"recovery-v1",3,1)
  self.new=policy(self.new_keys,"recovery-v2",3,1)
  self.guardians=policy(self.guardian_keys,"break-glass-v1",4,1)
  self.new_signers={k:RecoveryAuthoritySigner(k,v,pathlib.Path(self.tmp.name)/(k+".sqlite"))
   for k,v in self.new_keys.items()}
  self.guardian_signers={k:RecoveryAuthoritySigner(k,v,pathlib.Path(self.tmp.name)/(k+".sqlite"))
   for k,v in self.guardian_keys.items()}
  self.head="a"*64; self.incident="b"*64
  self.rotation=make_emergency_rotation(self.old,self.new,self.guardians,7,
   self.head,self.incident,"QUORUM_LOSS",
   {k:self.guardian_signers[k] for k in list(self.guardian_signers)[:4]},
   {k:self.new_signers[k] for k in list(self.new_signers)[:3]})
 def test_four_of_five_guardians_plus_incoming_quorum_accept(self):
  self.assertTrue(verify_emergency_rotation(self.old,self.new,self.guardians,
   self.rotation,7,self.head))
 def test_active_old_council_signature_is_not_required(self):
  self.assertNotIn("outgoing_approval",self.rotation)
  self.assertTrue(verify_emergency_rotation(self.old,self.new,self.guardians,
   self.rotation,7,self.head))
 def test_three_guardians_are_insufficient(self):
  b=copy.deepcopy(self.rotation); b["guardian_approval"]["approvals"]=b["guardian_approval"]["approvals"][:3]
  self.assertFalse(verify_emergency_rotation(self.old,self.new,self.guardians,b,7,self.head))
 def test_incoming_council_must_accept(self):
  b=copy.deepcopy(self.rotation); b["incoming_acceptance"]["approvals"]=b["incoming_acceptance"]["approvals"][:2]
  self.assertFalse(verify_emergency_rotation(self.old,self.new,self.guardians,b,7,self.head))
 def test_registry_head_substitution_rejected(self):
  self.assertFalse(verify_emergency_rotation(self.old,self.new,self.guardians,
   self.rotation,7,"f"*64))
 def test_incident_commitment_tampering_rejected(self):
  b=copy.deepcopy(self.rotation); b["payload"]["incident_sha256"]="f"*64
  self.assertFalse(verify_emergency_rotation(self.old,self.new,self.guardians,b,7,self.head))
 def test_reason_tampering_rejected(self):
  b=copy.deepcopy(self.rotation); b["payload"]["reason"]="AI_REQUESTED_OVERRIDE"
  self.assertFalse(verify_emergency_rotation(self.old,self.new,self.guardians,b,7,self.head))
 def test_wrong_emergency_policy_rejected(self):
  other_keys={f"other-{i}":Ed25519PrivateKey.generate() for i in range(5)}
  other=policy(other_keys,"break-glass-v2",4,1)
  self.assertFalse(verify_emergency_rotation(self.old,self.new,other,self.rotation,7,self.head))
 def test_successor_key_overlap_rejected(self):
  overlap=dict(self.new_keys); overlap["new-0"]=self.old_keys["old-0"]
  bad=policy(overlap,"recovery-v3",3,1)
  with self.assertRaisesRegex(ValueError,"disjoint public keys"):
   make_emergency_rotation(self.old,bad,self.guardians,7,self.head,self.incident,
    "QUORUM_LOSS",{}, {})
 def test_successor_admin_domain_overlap_rejected(self):
  bad=copy.deepcopy(self.new)
  bad["administrative_domains"]["new-0"]=self.old["administrative_domains"]["old-0"]
  with self.assertRaisesRegex(ValueError,"disjoint administrative domains"):
   make_emergency_rotation(self.old,bad,self.guardians,7,self.head,self.incident,
    "QUORUM_LOSS",{}, {})
 def test_emergency_rotation_cannot_reduce_fault_bound(self):
  weak=copy.deepcopy(self.new); weak["max_faults"]=0
  with self.assertRaisesRegex(ValueError,"reduce Byzantine fault bound"):
   make_emergency_rotation(self.old,weak,self.guardians,7,self.head,self.incident,
    "QUORUM_LOSS",{}, {})
 def test_generation_replay_rejected(self):
  self.assertFalse(verify_emergency_rotation(self.old,self.new,self.guardians,
   self.rotation,8,self.head))

 def test_guardian_keys_must_be_independent_from_recovery_councils(self):
  overlap=dict(self.guardian_keys)
  overlap["guardian-0"]=self.old_keys["old-0"]
  bad=policy(overlap,"break-glass-overlap",4,1)
  with self.assertRaisesRegex(ValueError,"guardians must use keys disjoint"):
   make_emergency_rotation(self.old,self.new,bad,7,self.head,self.incident,
    "QUORUM_LOSS",{}, {})
 def test_guardian_administrative_domains_must_be_independent(self):
  bad=copy.deepcopy(self.guardians)
  bad["administrative_domains"]["guardian-0"]=self.new["administrative_domains"]["new-0"]
  with self.assertRaisesRegex(ValueError,"guardians must use disjoint administrative domains"):
   make_emergency_rotation(self.old,self.new,bad,7,self.head,self.incident,
    "QUORUM_LOSS",{}, {})
 def test_emergency_guardian_fault_bound_cannot_be_weaker(self):
  weak_guardians=copy.deepcopy(self.guardians)
  weak_guardians["max_faults"]=0
  with self.assertRaisesRegex(ValueError,"guardian council cannot reduce Byzantine fault bound"):
   make_emergency_rotation(self.old,self.new,weak_guardians,7,self.head,self.incident,
    "QUORUM_LOSS",{}, {})
