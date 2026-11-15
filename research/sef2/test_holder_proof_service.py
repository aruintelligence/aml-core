import json,pathlib,tempfile,unittest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from holder_proof_service import HolderProofState
from session_capability import issue_session_capability,verify_holder_proof
from authenticated_execution_challenge import make_execution_challenge

class HolderProofStateTests(unittest.TestCase):
 def setUp(self):
  t=tempfile.TemporaryDirectory(); self.addCleanup(t.cleanup); self.root=pathlib.Path(t.name)
  self.key=Ed25519PrivateKey.generate(); self.other=Ed25519PrivateKey.generate()
  self.authority=Ed25519PrivateKey.generate()
  self.request={"operation_id":"holder-op","action":"payment:simulate","target":"fixture:merchant-a","amount_cents":100}
  self.cap=issue_session_capability(self.authority,"issuer","broker",self.request,0,self.key.public_key().public_bytes_raw().hex())
  self.state=HolderProofState(self.root/"holder.sqlite",self.key)
 def test_register_and_prove_exact_session(self):
  self.assertEqual(self.state.register(self.cap,self.request),"REGISTERED")
  proof=self.state.prove(self.cap,self.request,"a"*64)
  self.assertTrue(verify_holder_proof(proof,self.cap,self.request,"a"*64))
 def test_conflicting_registration_same_operation_rejected(self):
  self.state.register(self.cap,self.request)
  changed=dict(self.request,amount_cents=101)
  cap2=issue_session_capability(self.authority,"issuer","broker",changed,0,self.key.public_key().public_bytes_raw().hex())
  with self.assertRaises(PermissionError): self.state.register(cap2,changed)
 def test_capability_for_other_holder_rejected(self):
  cap=issue_session_capability(self.authority,"issuer","broker",self.request,0,self.other.public_key().public_bytes_raw().hex())
  with self.assertRaises(PermissionError): self.state.register(cap,self.request)
 def test_unregistered_proof_request_rejected(self):
  with self.assertRaises(PermissionError): self.state.prove(self.cap,self.request,"a"*64)
 def test_challenge_reuse_across_operations_rejected(self):
  self.state.register(self.cap,self.request); self.state.prove(self.cap,self.request,"a"*64)
  req2=dict(self.request,operation_id="holder-op-2")
  cap2=issue_session_capability(self.authority,"issuer","broker",req2,0,self.key.public_key().public_bytes_raw().hex())
  self.state.register(cap2,req2)
  with self.assertRaises(PermissionError): self.state.prove(cap2,req2,"a"*64)
 def test_same_challenge_same_operation_is_idempotent(self):
  self.state.register(self.cap,self.request)
  one=self.state.prove(self.cap,self.request,"a"*64); two=self.state.prove(self.cap,self.request,"a"*64)
  self.assertEqual(one,two)

class AuthenticatedHolderProofStateTests(unittest.TestCase):
 def setUp(self):
  x=tempfile.TemporaryDirectory(); self.addCleanup(x.cleanup); self.root=pathlib.Path(x.name)
  self.key=Ed25519PrivateKey.generate(); self.broker=Ed25519PrivateKey.generate(); self.fake=Ed25519PrivateKey.generate()
  self.authority=Ed25519PrivateKey.generate()
  self.request={"operation_id":"holder-auth-op","action":"payment:simulate","target":"fixture:merchant-a","amount_cents":100}
  self.cap=issue_session_capability(self.authority,"issuer","broker",self.request,3,self.key.public_key().public_bytes_raw().hex())
  self.state=HolderProofState(self.root/"holder-auth.sqlite",self.key,
   self.broker.public_key().public_bytes_raw().hex(),"broker-instance","broker")
  self.state.register(self.cap,self.request)
 def env(self,key=None,request=None,cap=None,epoch=3):
  return make_execution_challenge(key or self.broker,"broker-instance","broker",request or self.request,
   cap or self.cap,epoch,"c"*64)
 def test_pinned_broker_challenge_produces_holder_proof(self):
  env=self.env(); proof=self.state.prove_authenticated(self.cap,self.request,env)
  self.assertTrue(verify_holder_proof(proof,self.cap,self.request,env["payload"]["challenge"]))
 def test_raw_runtime_challenge_disabled_in_authenticated_mode(self):
  with self.assertRaises(PermissionError): self.state.prove(self.cap,self.request,"c"*64)
 def test_impostor_broker_cannot_elicit_holder_proof(self):
  with self.assertRaises(PermissionError): self.state.prove_authenticated(self.cap,self.request,self.env(key=self.fake))
 def test_broker_challenge_request_substitution_rejected(self):
  changed=dict(self.request,amount_cents=101)
  with self.assertRaises(PermissionError): self.state.prove_authenticated(self.cap,changed,self.env())
 def test_broker_challenge_capability_substitution_rejected(self):
  other_holder=Ed25519PrivateKey.generate()
  cap2=issue_session_capability(self.authority,"issuer","broker",self.request,3,other_holder.public_key().public_bytes_raw().hex())
  with self.assertRaises(PermissionError): self.state.prove_authenticated(cap2,self.request,self.env())
