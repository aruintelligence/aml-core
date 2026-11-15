import concurrent.futures,copy,pathlib,shutil,sqlite3,tempfile,unittest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pin_registry import PinRegistry
from pin_replication import PinReplica
from replica_attestation import attest
from session_epoch_anchor import SessionEpochAnchor
from session_capability import issue_session_capability,make_holder_proof
from authenticated_execution_challenge import make_execution_challenge
from execution_gate_receipt import evaluate_and_issue
from independent_effect_executor import IndependentEffectExecutor
from execution_consumption_witness import ExecutionConsumptionWitness

class IndependentEffectExecutorTests(unittest.TestCase):
 def setUp(self):
  tmp=tempfile.TemporaryDirectory(); self.addCleanup(tmp.cleanup); root=pathlib.Path(tmp.name)
  self.registry=PinRegistry(root/"registry.sqlite"); self.registry.enroll("north","a"*64)
  self.replicas=[PinReplica(root/(f"replica-{i}.sqlite")) for i in range(3)]
  self.replica_keys=[Ed25519PrivateKey.generate() for _ in range(3)]
  self.enrolled={f"r{i}":k.public_key().public_bytes_raw().hex() for i,k in enumerate(self.replica_keys)}
  for r in self.replicas: r.record("north",0,"a"*64)
  self.authority=Ed25519PrivateKey.generate(); self.broker=Ed25519PrivateKey.generate()
  self.holder=Ed25519PrivateKey.generate(); self.evaluator=Ed25519PrivateKey.generate()
  self.anchor=SessionEpochAnchor(root/"epoch.sqlite"); self.anchor.initialize("broker-a",0)
  self.request={"operation_id":"independent-effect-op","action":"payment:simulate",
   "target":"fixture:merchant-a","amount_cents":100}
  self.capability=issue_session_capability(self.authority,"authority","broker-a",self.request,0,
   self.holder.public_key().public_bytes_raw().hex())
  self.challenge=make_execution_challenge(self.broker,"broker-instance-1","broker-a",
   self.request,self.capability,0,"c"*64)
  self.holder_proof=make_holder_proof(self.holder,self.capability,self.request,"c"*64)
  self.attestations=[attest(r,f"r{i}","north",self.replica_keys[i]) for i,r in enumerate(self.replicas)]
  self.evaluator_auth=evaluate_and_issue(self.registry,"north",self.replicas,2,self.attestations,
   self.enrolled,self.evaluator,"evaluator-1","broker-a",self.request,self.capability,self.challenge,0)
  self.executor=IndependentEffectExecutor(root/"executor.sqlite","authority",
   self.authority.public_key().public_bytes_raw().hex(),"broker-a","broker-instance-1",
   self.broker.public_key().public_bytes_raw().hex(),"evaluator-1",
   self.evaluator.public_key().public_bytes_raw().hex(),"north",self.anchor)
 def execute(self,cap=None,challenge=None,proof=None,evaluator=None,request=None):
  return self.executor.execute(request or self.request,cap or self.capability,
   challenge or self.challenge,proof or self.holder_proof,evaluator or self.evaluator_auth)
 def count(self):
  with sqlite3.connect(self.executor.path) as db:
   return db.execute("SELECT COUNT(*) FROM independent_effects").fetchone()[0]
 def test_all_independent_evidence_commits_once(self):
  self.assertEqual(self.execute(),"APPLIED")
  self.assertEqual(self.execute(),"ALREADY_APPLIED")
  self.assertEqual(self.count(),1)
 def test_forged_authority_capability_rejected(self):
  cap=copy.deepcopy(self.capability); cap["signature"]="00"*64
  self.assertEqual(self.execute(cap=cap),"DENIED"); self.assertEqual(self.count(),0)
 def test_forged_broker_challenge_rejected(self):
  challenge=copy.deepcopy(self.challenge); challenge["signature"]="00"*64
  self.assertEqual(self.execute(challenge=challenge),"DENIED"); self.assertEqual(self.count(),0)
 def test_forged_holder_proof_rejected(self):
  proof=copy.deepcopy(self.holder_proof); proof["signature"]="00"*64
  self.assertEqual(self.execute(proof=proof),"DENIED"); self.assertEqual(self.count(),0)
 def test_forged_evaluator_authorization_rejected(self):
  evaluator=copy.deepcopy(self.evaluator_auth); evaluator["signature"]="00"*64
  self.assertEqual(self.execute(evaluator=evaluator),"DENIED"); self.assertEqual(self.count(),0)
 def test_revocation_epoch_blocks_old_evidence(self):
  self.assertTrue(self.anchor.compare_and_set("broker-a",0,1))
  self.assertEqual(self.execute(),"DENIED"); self.assertEqual(self.count(),0)
 def test_request_substitution_rejected(self):
  self.assertEqual(self.execute(request=dict(self.request,amount_cents=101)),"DENIED")
 def test_evaluator_refuses_invalid_replica_evidence(self):
  with self.assertRaises(PermissionError):
   evaluate_and_issue(self.registry,"north",self.replicas,2,[],self.enrolled,
    self.evaluator,"evaluator-1","broker-a",self.request,self.capability,self.challenge,0)
 def test_wrong_evaluator_key_rejected(self):
  other=Ed25519PrivateKey.generate()
  executor=IndependentEffectExecutor(pathlib.Path(self.executor.path).with_name("wrong-eval.sqlite"),
   "authority",self.authority.public_key().public_bytes_raw().hex(),"broker-a","broker-instance-1",
   self.broker.public_key().public_bytes_raw().hex(),"evaluator-1",
   other.public_key().public_bytes_raw().hex(),"north",self.anchor)
  self.assertEqual(executor.execute(self.request,self.capability,self.challenge,
   self.holder_proof,self.evaluator_auth),"DENIED")
 def test_revocation_race_between_verification_and_commit_fails_closed(self):
  class FlippingAnchor:
   def __init__(self): self.calls=0
   def read_epoch(self,audience):
    self.calls+=1
    return 0 if self.calls==1 else 1
  executor=IndependentEffectExecutor(pathlib.Path(self.executor.path).with_name("race.sqlite"),
   "authority",self.authority.public_key().public_bytes_raw().hex(),"broker-a","broker-instance-1",
   self.broker.public_key().public_bytes_raw().hex(),"evaluator-1",
   self.evaluator.public_key().public_bytes_raw().hex(),"north",FlippingAnchor())
  self.assertEqual(executor.execute(self.request,self.capability,self.challenge,
   self.holder_proof,self.evaluator_auth),"DENIED")
 def test_concurrent_duplicate_commit_is_exactly_once(self):
  with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
   results=list(pool.map(lambda _:self.execute(),range(2)))
  self.assertEqual(results.count("APPLIED"),1)
  self.assertEqual(results.count("ALREADY_APPLIED"),1)
  self.assertEqual(self.count(),1)

 def test_executor_database_rollback_cannot_repeat_consumed_effect(self):
  root=pathlib.Path(self.executor.path).parent
  witness=ExecutionConsumptionWitness(root/"executor-consumption.sqlite")
  executor=IndependentEffectExecutor(root/"rollback-executor.sqlite","authority",
   self.authority.public_key().public_bytes_raw().hex(),"broker-a","broker-instance-1",
   self.broker.public_key().public_bytes_raw().hex(),"evaluator-1",
   self.evaluator.public_key().public_bytes_raw().hex(),"north",self.anchor,witness)
  # Initialize database and snapshot before the first effect.
  snapshot=root/"executor-before-effect.sqlite"; shutil.copy2(executor.path,snapshot)
  self.assertEqual(executor.execute(self.request,self.capability,self.challenge,
   self.holder_proof,self.evaluator_auth),"APPLIED")
  shutil.copy2(snapshot,executor.path)
  restarted=IndependentEffectExecutor(executor.path,"authority",
   self.authority.public_key().public_bytes_raw().hex(),"broker-a","broker-instance-1",
   self.broker.public_key().public_bytes_raw().hex(),"evaluator-1",
   self.evaluator.public_key().public_bytes_raw().hex(),"north",self.anchor,witness)
  self.assertEqual(restarted.execute(self.request,self.capability,self.challenge,
   self.holder_proof,self.evaluator_auth),"DENIED")
  with sqlite3.connect(executor.path) as db:
   self.assertEqual(db.execute("SELECT COUNT(*) FROM independent_effects").fetchone()[0],0)
 def test_executor_witness_consumption_then_local_failure_strands_operation(self):
  root=pathlib.Path(self.executor.path).parent
  witness=ExecutionConsumptionWitness(root/"stranded-consumption.sqlite")
  executor=IndependentEffectExecutor(root/"stranded-executor.sqlite","authority",
   self.authority.public_key().public_bytes_raw().hex(),"broker-a","broker-instance-1",
   self.broker.public_key().public_bytes_raw().hex(),"evaluator-1",
   self.evaluator.public_key().public_bytes_raw().hex(),"north",self.anchor,witness)
  with sqlite3.connect(executor.path) as db:
   db.execute("""CREATE TRIGGER reject_independent_effect BEFORE INSERT ON independent_effects
    BEGIN SELECT RAISE(ABORT,'injected executor failure'); END""")
  self.assertEqual(executor.execute(self.request,self.capability,self.challenge,
   self.holder_proof,self.evaluator_auth),"DENIED")
  self.assertIsNotNone(witness.lookup(self.request["operation_id"]))
  with sqlite3.connect(executor.path) as db:
   db.execute("DROP TRIGGER reject_independent_effect")
  self.assertEqual(executor.execute(self.request,self.capability,self.challenge,
   self.holder_proof,self.evaluator_auth),"DENIED")
