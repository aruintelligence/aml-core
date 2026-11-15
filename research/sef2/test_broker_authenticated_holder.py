import copy,unittest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from authenticated_execution_challenge import make_execution_challenge
from session_capability import issue_session_capability,verify_holder_proof
from broker_authenticated_holder import make_broker_authenticated_holder_proof

class BrokerAuthenticatedHolderTests(unittest.TestCase):
 def setUp(self):
  self.authority=Ed25519PrivateKey.generate()
  self.broker=Ed25519PrivateKey.generate()
  self.holder=Ed25519PrivateKey.generate()
  self.request={"operation_id":"auth-holder-op","action":"payment:simulate",
   "target":"fixture:merchant-a","amount_cents":100}
  self.cap=issue_session_capability(self.authority,"authority","broker-a",self.request,3,
   self.holder.public_key().public_bytes_raw().hex())
  self.challenge=make_execution_challenge(self.broker,"broker-instance-1","broker-a",
   self.request,self.cap,3,"c"*64)
  self.broker_public=self.broker.public_key().public_bytes_raw().hex()
 def proof(self,challenge=None,request=None,cap=None,pub=None,broker_id="broker-instance-1"):
  return make_broker_authenticated_holder_proof(self.holder,challenge or self.challenge,
   pub or self.broker_public,broker_id,"broker-a",cap or self.cap,request or self.request)
 def test_exact_broker_authenticated_challenge_accepts(self):
  proof=self.proof()
  self.assertTrue(verify_holder_proof(proof,self.cap,self.request,"c"*64))
 def test_forged_broker_signature_rejected(self):
  changed=copy.deepcopy(self.challenge); changed["signature"]="00"*64
  with self.assertRaises(PermissionError): self.proof(challenge=changed)
 def test_wrong_broker_key_rejected(self):
  with self.assertRaises(PermissionError):
   self.proof(pub=Ed25519PrivateKey.generate().public_key().public_bytes_raw().hex())
 def test_wrong_broker_identity_rejected(self):
  with self.assertRaises(PermissionError): self.proof(broker_id="broker-instance-2")
 def test_request_substitution_rejected(self):
  with self.assertRaises(PermissionError): self.proof(request=dict(self.request,amount_cents=101))
 def test_capability_substitution_rejected(self):
  replacement_holder=Ed25519PrivateKey.generate()
  cap=issue_session_capability(self.authority,"authority","broker-a",self.request,3,
   replacement_holder.public_key().public_bytes_raw().hex())
  self.assertNotEqual(cap,self.cap)
  with self.assertRaises(PermissionError): self.proof(cap=cap)
 def test_epoch_substitution_rejected(self):
  cap=issue_session_capability(self.authority,"authority","broker-a",self.request,4,
   self.holder.public_key().public_bytes_raw().hex())
  with self.assertRaises(PermissionError): self.proof(cap=cap)
 def test_raw_challenge_string_is_not_accepted(self):
  with self.assertRaises((PermissionError,TypeError,AttributeError)):
   self.proof(challenge="c"*64)
