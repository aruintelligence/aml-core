import pathlib,sqlite3,tempfile,unittest,concurrent.futures
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pin_registry import PinRegistry
from pin_replication import PinReplica
from replica_attestation import attest
from session_capability import issue_session_capability,make_holder_proof
from session_capability_broker import SessionCapabilityBroker

class SessionCapabilityBrokerTests(unittest.TestCase):
 def setUp(self):
  tmp=tempfile.TemporaryDirectory(); self.addCleanup(tmp.cleanup); root=pathlib.Path(tmp.name)
  self.registry=PinRegistry(root/"evaluator.sqlite"); self.registry.enroll("north","a"*64)
  self.replicas=[PinReplica(root/(f"r{i}.sqlite")) for i in range(3)]
  self.replica_keys=[Ed25519PrivateKey.generate() for _ in range(3)]
  self.enrolled={f"r{i}":k.public_key().public_bytes_raw().hex() for i,k in enumerate(self.replica_keys)}
  for r in self.replicas: r.record("north",0,"a"*64)
  self.issuer=Ed25519PrivateKey.generate(); self.holder=Ed25519PrivateKey.generate(); self.other=Ed25519PrivateKey.generate()
  self.broker_instance_key=Ed25519PrivateKey.generate()
  self.request={"operation_id":"session-op","action":"payment:simulate","target":"fixture:merchant-a","amount_cents":100}
  self.broker=SessionCapabilityBroker(root/"effects.sqlite",self.registry,"north",self.replicas,2,
   self.enrolled,"authority",self.issuer.public_key().public_bytes_raw().hex(),"broker-a",
   "broker-instance-test",self.broker_instance_key)
 def signed(self):
  return [attest(r,f"r{i}","north",self.replica_keys[i]) for i,r in enumerate(self.replicas)]
 def capability(self,request=None,epoch=None,holder=None):
  return issue_session_capability(self.issuer,"authority","broker-a",request or self.request,
   self.broker.current_epoch() if epoch is None else epoch,
   (holder or self.holder).public_key().public_bytes_raw().hex())
 def execute_valid(self,request=None):
  request=request or self.request; cap=self.capability(request=request)
  challenge=self.broker.issue_execution_challenge(request["operation_id"])
  proof=make_holder_proof(self.holder,cap,request,challenge)
  return self.broker.execute(request,self.signed(),cap,proof,challenge)
 def count(self):
  with sqlite3.connect(self.broker.path) as db:
   return db.execute("SELECT COUNT(*) FROM session_effects").fetchone()[0]
 def test_fresh_holder_proof_executes_once(self):
  self.assertEqual(self.execute_valid(),"APPLIED"); self.assertEqual(self.count(),1)
 def test_bearer_capability_without_holder_proof_denied(self):
  cap=self.capability(); challenge=self.broker.issue_execution_challenge(self.request["operation_id"])
  self.assertEqual(self.broker.execute(self.request,self.signed(),cap,None,challenge),"DENIED")
  self.assertEqual(self.count(),0)
 def test_wrong_holder_private_key_cannot_generate_proof(self):
  cap=self.capability(); challenge=self.broker.issue_execution_challenge(self.request["operation_id"])
  with self.assertRaises(ValueError): make_holder_proof(self.other,cap,self.request,challenge)
 def test_old_proof_rejected_for_new_operation_challenge(self):
  cap=self.capability(); challenge=self.broker.issue_execution_challenge(self.request["operation_id"])
  proof=make_holder_proof(self.holder,cap,self.request,challenge)
  changed=dict(self.request,operation_id="session-op-2")
  cap2=self.capability(request=changed); challenge2=self.broker.issue_execution_challenge(changed["operation_id"])
  self.assertEqual(self.broker.execute(changed,self.signed(),cap2,proof,challenge2),"DENIED")
 def test_challenge_is_single_use_after_effect_commit(self):
  cap=self.capability(); challenge=self.broker.issue_execution_challenge(self.request["operation_id"])
  proof=make_holder_proof(self.holder,cap,self.request,challenge)
  self.assertEqual(self.broker.execute(self.request,self.signed(),cap,proof,challenge),"APPLIED")
  self.assertEqual(self.broker.execute(self.request,self.signed(),cap,proof,challenge),"DENIED")
  with self.assertRaises(PermissionError): self.broker.issue_execution_challenge(self.request["operation_id"])
 def test_policy_revocation_invalidates_capability_and_challenge(self):
  cap=self.capability(); challenge=self.broker.issue_execution_challenge(self.request["operation_id"])
  proof=make_holder_proof(self.holder,cap,self.request,challenge)
  self.broker.revoke_all()
  self.assertEqual(self.broker.execute(self.request,self.signed(),cap,proof,challenge),"DENIED")
  self.assertEqual(self.count(),0)
 def test_request_substitution_denied(self):
  cap=self.capability(); challenge=self.broker.issue_execution_challenge(self.request["operation_id"])
  proof=make_holder_proof(self.holder,cap,self.request,challenge)
  changed=dict(self.request,amount_cents=101)
  self.assertEqual(self.broker.execute(changed,self.signed(),cap,proof,challenge),"DENIED")
 def test_missing_evaluator_attestations_denied(self):
  cap=self.capability(); challenge=self.broker.issue_execution_challenge(self.request["operation_id"])
  proof=make_holder_proof(self.holder,cap,self.request,challenge)
  self.assertEqual(self.broker.execute(self.request,[],cap,proof,challenge),"DENIED")
 def test_restart_preserves_challenge_and_epoch(self):
  cap=self.capability(); challenge=self.broker.issue_execution_challenge(self.request["operation_id"])
  restarted=SessionCapabilityBroker(self.broker.path,self.registry,"north",self.replicas,2,self.enrolled,
   "authority",self.issuer.public_key().public_bytes_raw().hex(),"broker-a")
  proof=make_holder_proof(self.holder,cap,self.request,challenge)
  self.assertEqual(restarted.execute(self.request,self.signed(),cap,proof,challenge),"APPLIED")
 def test_concurrent_duplicate_execution_commits_once(self):
  cap=self.capability(); challenge=self.broker.issue_execution_challenge(self.request["operation_id"])
  proof=make_holder_proof(self.holder,cap,self.request,challenge)
  with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
   results=list(pool.map(lambda _:self.broker.execute(self.request,self.signed(),cap,proof,challenge),range(2)))
  self.assertEqual(results.count("APPLIED"),1)
  self.assertEqual(sum(r in ("APPLIED","DENIED") for r in results),2)
  self.assertEqual(self.count(),1)

 def test_broker_authenticated_challenge_binds_exact_capability_and_request(self):
  from authenticated_execution_challenge import verify_execution_challenge
  cap=self.capability()
  envelope=self.broker.issue_authenticated_execution_challenge(self.request,cap)
  self.assertTrue(verify_execution_challenge(envelope,
   self.broker_instance_key.public_key().public_bytes_raw().hex(),"broker-instance-test",
   "broker-a",self.request,cap,self.broker.current_epoch()))
 def test_broker_refuses_to_sign_challenge_for_invalid_capability(self):
  cap=self.capability(); cap["signature"]="00"*64
  with self.assertRaises(PermissionError):
   self.broker.issue_authenticated_execution_challenge(self.request,cap)
 def test_broker_authenticated_challenge_invalidated_by_policy_revocation(self):
  cap=self.capability(); envelope=self.broker.issue_authenticated_execution_challenge(self.request,cap)
  self.broker.revoke_all()
  from authenticated_execution_challenge import verify_execution_challenge
  self.assertFalse(verify_execution_challenge(envelope,
   self.broker_instance_key.public_key().public_bytes_raw().hex(),"broker-instance-test",
   "broker-a",self.request,cap,self.broker.current_epoch()))
