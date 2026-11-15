import copy,unittest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from threshold_recovery import POLICY_SCHEMA
from recovery_policy_rotation import make_policy_rotation,verify_policy_rotation

def policy(keys,policy_id):
 return {"schema":POLICY_SCHEMA,"policy_id":policy_id,"threshold":3,"max_faults":1,
   "authorities":{k:v.public_key().public_bytes_raw().hex() for k,v in keys.items()}}

class RecoveryPolicyRotationTests(unittest.TestCase):
 def setUp(self):
  self.old={f"old-{i}":Ed25519PrivateKey.generate() for i in range(4)}
  self.new={f"new-{i}":Ed25519PrivateKey.generate() for i in range(4)}
  self.current=policy(self.old,"council-v1")
  self.next=policy(self.new,"council-v2")
  self.bundle=make_policy_rotation(self.current,self.next,2,
    {k:self.old[k] for k in ("old-0","old-1","old-2")},
    {k:self.new[k] for k in ("new-0","new-1","new-2")})
 def test_rotation_requires_and_accepts_both_quorums(self):
  self.assertTrue(verify_policy_rotation(self.current,self.next,self.bundle,2))
 def test_outgoing_quorum_cannot_rotate_without_incoming_acceptance(self):
  b=copy.deepcopy(self.bundle); b["incoming_acceptance"]["approvals"]=b["incoming_acceptance"]["approvals"][:2]
  self.assertFalse(verify_policy_rotation(self.current,self.next,b,2))
 def test_incoming_quorum_cannot_self_install(self):
  b=copy.deepcopy(self.bundle); b["outgoing_approval"]["approvals"]=b["outgoing_approval"]["approvals"][:2]
  self.assertFalse(verify_policy_rotation(self.current,self.next,b,2))
 def test_policy_substitution_rejected(self):
  other=policy({f"other-{i}":Ed25519PrivateKey.generate() for i in range(4)},"council-v3")
  self.assertFalse(verify_policy_rotation(self.current,other,self.bundle,2))
 def test_wrong_generation_rejected(self): self.assertFalse(verify_policy_rotation(self.current,self.next,self.bundle,3))
 def test_rollback_to_old_policy_rejected(self):
  self.assertFalse(verify_policy_rotation(self.next,self.current,self.bundle,3))
 def test_payload_generation_tampering_rejected(self):
  b=copy.deepcopy(self.bundle); b["payload"]["generation"]=3
  self.assertFalse(verify_policy_rotation(self.current,self.next,b,2))
 def test_incoming_acceptance_tampering_rejected(self):
  b=copy.deepcopy(self.bundle); b["incoming_acceptance"]["approvals"][0]["signature"]="00"*64
  self.assertFalse(verify_policy_rotation(self.current,self.next,b,2))
 def test_outgoing_approval_tampering_rejected(self):
  b=copy.deepcopy(self.bundle); b["outgoing_approval"]["approvals"][0]["signature"]="00"*64
  self.assertFalse(verify_policy_rotation(self.current,self.next,b,2))
 def test_same_policy_cannot_rotate_to_itself(self):
  with self.assertRaises(ValueError):
   make_policy_rotation(self.current,self.current,2,
    {k:self.old[k] for k in ("old-0","old-1","old-2")},
    {k:self.old[k] for k in ("old-0","old-1","old-2")})
