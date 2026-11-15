import copy,unittest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from session_capability import (issue_session_capability,verify_session_capability,
 make_holder_proof,verify_holder_proof)
class SessionCapabilityTests(unittest.TestCase):
 def setUp(self):
  self.authority=Ed25519PrivateKey.generate(); self.holder=Ed25519PrivateKey.generate()
  self.other=Ed25519PrivateKey.generate()
  self.request={"operation_id":"session-op","action":"payment:simulate",
   "target":"fixture:merchant-a","amount_cents":100}
  self.cap=issue_session_capability(self.authority,"issuer","broker",self.request,7,
   self.holder.public_key().public_bytes_raw().hex())
  self.challenge="c"*64
 def test_capability_and_holder_proof_accept(self):
  self.assertTrue(verify_session_capability(self.cap,self.authority.public_key().public_bytes_raw().hex(),
   "issuer","broker",self.request,7))
  proof=make_holder_proof(self.holder,self.cap,self.request,self.challenge)
  self.assertTrue(verify_holder_proof(proof,self.cap,self.request,self.challenge))
 def test_stolen_capability_without_holder_key_cannot_make_proof(self):
  with self.assertRaises(ValueError):
   make_holder_proof(self.other,self.cap,self.request,self.challenge)
 def test_forged_holder_signature_rejected(self):
  proof=make_holder_proof(self.holder,self.cap,self.request,self.challenge)
  proof["signature"]="00"*64
  self.assertFalse(verify_holder_proof(proof,self.cap,self.request,self.challenge))
 def test_fresh_challenge_binding_prevents_old_proof_reuse(self):
  proof=make_holder_proof(self.holder,self.cap,self.request,self.challenge)
  self.assertFalse(verify_holder_proof(proof,self.cap,self.request,"d"*64))
 def test_request_substitution_rejected(self):
  proof=make_holder_proof(self.holder,self.cap,self.request,self.challenge)
  changed=dict(self.request,amount_cents=101)
  self.assertFalse(verify_holder_proof(proof,self.cap,changed,self.challenge))
  self.assertFalse(verify_session_capability(self.cap,self.authority.public_key().public_bytes_raw().hex(),
   "issuer","broker",changed,7))
 def test_capability_holder_key_substitution_breaks_authority_signature(self):
  changed=copy.deepcopy(self.cap)
  changed["payload"]["holder_public_key_hex"]=self.other.public_key().public_bytes_raw().hex()
  self.assertFalse(verify_session_capability(changed,self.authority.public_key().public_bytes_raw().hex(),
   "issuer","broker",self.request,7))
 def test_policy_epoch_revocation_rejected(self):
  self.assertFalse(verify_session_capability(self.cap,self.authority.public_key().public_bytes_raw().hex(),
   "issuer","broker",self.request,8))
 def test_wrong_audience_rejected(self):
  self.assertFalse(verify_session_capability(self.cap,self.authority.public_key().public_bytes_raw().hex(),
   "issuer","other",self.request,7))
 def test_malformed_holder_key_rejected(self):
  with self.assertRaises(ValueError):
   issue_session_capability(self.authority,"issuer","broker",self.request,7,"00")
 def test_proof_is_bound_to_exact_capability_bytes(self):
  proof=make_holder_proof(self.holder,self.cap,self.request,self.challenge)
  changed=copy.deepcopy(self.cap); changed["signature"]="00"*64
  self.assertFalse(verify_holder_proof(proof,changed,self.request,self.challenge))
