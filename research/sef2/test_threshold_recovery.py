import copy,unittest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from threshold_recovery import (POLICY_SCHEMA,make_approval_bundle,
    validate_policy,verify_approval_bundle)

def make_policy(keys,threshold=2):
 return {"schema":POLICY_SCHEMA,"policy_id":"recovery-council-1","threshold":threshold,
     "authorities":{name:key.public_key().public_bytes_raw().hex() for name,key in keys.items()}}

class ThresholdRecoveryTests(unittest.TestCase):
 def setUp(self):
  self.keys={f"authority-{i}":Ed25519PrivateKey.generate() for i in range(4)}
  self.policy=make_policy(self.keys,3)
  self.payload={"witness_id":"north","generation":7,"new_key":"a"*64}
  self.bundle=make_approval_bundle(self.payload,self.policy,{k:self.keys[k] for k in ("authority-0","authority-1","authority-2")})
 def test_three_of_four_approvals_succeed(self):
  self.assertTrue(verify_approval_bundle(self.payload,self.bundle,self.policy))
 def test_two_of_four_is_insufficient(self):
  b=make_approval_bundle(self.payload,self.policy,{k:self.keys[k] for k in ("authority-0","authority-1")})
  self.assertFalse(verify_approval_bundle(self.payload,b,self.policy))
 def test_one_signer_cannot_be_counted_twice(self):
  b=copy.deepcopy(self.bundle); b["approvals"][1]=dict(b["approvals"][0])
  b["approvals"].sort(key=lambda x:x["authority_id"])
  self.assertFalse(verify_approval_bundle(self.payload,b,self.policy))
 def test_unknown_authority_rejected(self):
  b=copy.deepcopy(self.bundle); b["approvals"][0]["authority_id"]="unknown"
  self.assertFalse(verify_approval_bundle(self.payload,b,self.policy))
 def test_signature_tampering_rejected(self):
  b=copy.deepcopy(self.bundle); b["approvals"][0]["signature"]="00"*64
  self.assertFalse(verify_approval_bundle(self.payload,b,self.policy))
 def test_payload_substitution_rejected(self):
  self.assertFalse(verify_approval_bundle({**self.payload,"generation":8},self.bundle,self.policy))
 def test_policy_substitution_rejected(self):
  altered=copy.deepcopy(self.policy); altered["threshold"]=2
  self.assertFalse(verify_approval_bundle(self.payload,self.bundle,altered))
 def test_key_identity_substitution_rejected(self):
  altered=copy.deepcopy(self.policy); altered["authorities"]["authority-0"]=Ed25519PrivateKey.generate().public_key().public_bytes_raw().hex()
  self.assertFalse(verify_approval_bundle(self.payload,self.bundle,altered))
 def test_duplicate_public_keys_make_policy_invalid(self):
  altered=copy.deepcopy(self.policy); altered["authorities"]["authority-3"]=altered["authorities"]["authority-0"]
  self.assertFalse(validate_policy(altered))
 def test_invalid_threshold_rejected(self):
  for q in (0,5,True,2.5):
   altered=copy.deepcopy(self.policy); altered["threshold"]=q
   self.assertFalse(validate_policy(altered))
 def test_unsorted_approvals_rejected(self):
  b=copy.deepcopy(self.bundle); b["approvals"].reverse()
  self.assertFalse(verify_approval_bundle(self.payload,b,self.policy))
 def test_signer_key_mismatch_rejected_when_building(self):
  with self.assertRaises(ValueError):
   make_approval_bundle(self.payload,self.policy,{"authority-0":Ed25519PrivateKey.generate(),"authority-1":self.keys["authority-1"],"authority-2":self.keys["authority-2"]})
 def test_nonmember_signer_rejected_when_building(self):
  with self.assertRaises(ValueError):
   make_approval_bundle(self.payload,self.policy,{"outsider":Ed25519PrivateKey.generate()})
 def test_malformed_bundle_fails_closed(self):
  self.assertFalse(verify_approval_bundle(self.payload,{"approvals":[]},self.policy))
 def test_invalid_policy_fails_closed(self):
  self.assertFalse(verify_approval_bundle(self.payload,self.bundle,{"schema":"wrong"}))
