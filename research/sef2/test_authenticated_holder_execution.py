import pathlib,tempfile,unittest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pin_registry import PinRegistry
from pin_replication import PinReplica
from replica_attestation import attest
from holder_proof_service import HolderProofState
from session_capability import issue_session_capability
from session_capability_broker import SessionCapabilityBroker

class AuthenticatedHolderExecutionTests(unittest.TestCase):
 def setUp(self):
  t=tempfile.TemporaryDirectory(); self.addCleanup(t.cleanup); root=pathlib.Path(t.name)
  self.registry=PinRegistry(root/"eval.sqlite"); self.registry.enroll("north","a"*64)
  self.replicas=[PinReplica(root/f"r{i}.sqlite") for i in range(3)]
  self.replica_keys=[Ed25519PrivateKey.generate() for _ in range(3)]
  self.enrolled={f"r{i}":k.public_key().public_bytes_raw().hex() for i,k in enumerate(self.replica_keys)}
  for replica in self.replicas: replica.record("north",0,"a"*64)
  self.issuer=Ed25519PrivateKey.generate(); self.holder=Ed25519PrivateKey.generate()
  self.broker_key=Ed25519PrivateKey.generate(); self.fake_broker=Ed25519PrivateKey.generate()
  self.request={"operation_id":"end-to-end-holder","action":"payment:simulate","target":"fixture:merchant-a","amount_cents":100}
  self.broker=SessionCapabilityBroker(root/"broker.sqlite",self.registry,"north",self.replicas,2,
   self.enrolled,"authority",self.issuer.public_key().public_bytes_raw().hex(),"broker-a",
   "broker-instance-1",self.broker_key)
  self.cap=issue_session_capability(self.issuer,"authority","broker-a",self.request,0,
   self.holder.public_key().public_bytes_raw().hex())
  self.holder_state=HolderProofState(root/"holder.sqlite",self.holder,
   self.broker_key.public_key().public_bytes_raw().hex(),"broker-instance-1","broker-a")
  self.holder_state.register(self.cap,self.request)
 def attestations(self):
  return [attest(r,f"r{i}","north",self.replica_keys[i]) for i,r in enumerate(self.replicas)]
 def test_authenticated_broker_holder_broker_loop_applies_once(self):
  envelope=self.broker.issue_authenticated_execution_challenge(self.request,self.cap)
  proof=self.holder_state.prove_authenticated(self.cap,self.request,envelope)
  challenge=envelope["payload"]["challenge"]
  self.assertEqual(self.broker.execute(self.request,self.attestations(),self.cap,proof,challenge),"APPLIED")
  self.assertEqual(self.broker.execute(self.request,self.attestations(),self.cap,proof,challenge),"DENIED")
 def test_fake_broker_cannot_elicit_proof_even_with_exact_public_capability(self):
  from authenticated_execution_challenge import make_execution_challenge
  fake=make_execution_challenge(self.fake_broker,"broker-instance-1","broker-a",
   self.request,self.cap,0,"f"*64)
  with self.assertRaises(PermissionError):
   self.holder_state.prove_authenticated(self.cap,self.request,fake)
 def test_runtime_cannot_bypass_broker_signature_with_raw_challenge(self):
  with self.assertRaises(PermissionError):
   self.holder_state.prove(self.cap,self.request,"r"*64)
 def test_revocation_after_signed_challenge_prevents_execution(self):
  envelope=self.broker.issue_authenticated_execution_challenge(self.request,self.cap)
  proof=self.holder_state.prove_authenticated(self.cap,self.request,envelope)
  self.broker.revoke_all()
  self.assertEqual(self.broker.execute(self.request,self.attestations(),self.cap,proof,
   envelope["payload"]["challenge"]),"DENIED")
 def test_request_mutation_between_broker_challenge_and_holder_proof_is_denied(self):
  envelope=self.broker.issue_authenticated_execution_challenge(self.request,self.cap)
  changed=dict(self.request,amount_cents=101)
  with self.assertRaises(PermissionError):
   self.holder_state.prove_authenticated(self.cap,changed,envelope)
