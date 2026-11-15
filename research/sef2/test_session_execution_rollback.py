import pathlib,shutil,sqlite3,tempfile,unittest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from execution_consumption_witness import ExecutionConsumptionWitness
from pin_registry import PinRegistry
from pin_replication import PinReplica
from replica_attestation import attest
from session_capability import issue_session_capability,make_holder_proof
from session_capability_broker import SessionCapabilityBroker

class SessionExecutionRollbackTests(unittest.TestCase):
 def setUp(self):
  t=tempfile.TemporaryDirectory(); self.addCleanup(t.cleanup); self.root=pathlib.Path(t.name)
  self.registry=PinRegistry(self.root/"eval.sqlite"); self.registry.enroll("north","a"*64)
  self.replicas=[PinReplica(self.root/f"r{i}.sqlite") for i in range(3)]
  self.replica_keys=[Ed25519PrivateKey.generate() for _ in range(3)]
  self.enrolled={f"r{i}":k.public_key().public_bytes_raw().hex() for i,k in enumerate(self.replica_keys)}
  for r in self.replicas: r.record("north",0,"a"*64)
  self.issuer=Ed25519PrivateKey.generate(); self.holder=Ed25519PrivateKey.generate()
  self.path=self.root/"broker.sqlite"; self.witness=ExecutionConsumptionWitness(self.root/"execution-witness.sqlite")
  self.request={"operation_id":"rollback-execution-op","action":"payment:simulate","target":"fixture:merchant-a","amount_cents":100}
  self.broker=self.new_broker()
 def new_broker(self):
  return SessionCapabilityBroker(self.path,self.registry,"north",self.replicas,2,self.enrolled,
   "authority",self.issuer.public_key().public_bytes_raw().hex(),"broker-a",
   execution_witness=self.witness)
 def attestations(self):
  return [attest(r,f"r{i}","north",self.replica_keys[i]) for i,r in enumerate(self.replicas)]
 def prepare(self):
  cap=issue_session_capability(self.issuer,"authority","broker-a",self.request,0,
   self.holder.public_key().public_bytes_raw().hex())
  challenge=self.broker.issue_execution_challenge(self.request["operation_id"])
  proof=make_holder_proof(self.holder,cap,self.request,challenge)
  return cap,challenge,proof
 def test_broker_db_rollback_cannot_reexecute_consumed_operation(self):
  cap,challenge,proof=self.prepare()
  snapshot=self.root/"broker-before-execute.sqlite"; shutil.copy2(self.path,snapshot)
  self.assertEqual(self.broker.execute(self.request,self.attestations(),cap,proof,challenge),"APPLIED")
  self.assertIsNotNone(self.witness.lookup(self.request["operation_id"]))
  shutil.copy2(snapshot,self.path)
  restarted=self.new_broker()
  self.assertEqual(restarted.execute(self.request,self.attestations(),cap,proof,challenge),"DENIED")
  with sqlite3.connect(self.path) as db:
   self.assertEqual(db.execute("SELECT COUNT(*) FROM session_effects").fetchone()[0],0)
 def test_witness_unavailable_fails_closed_before_effect(self):
  class Down:
   def consume(self,*args): raise PermissionError("witness unavailable")
  cap,challenge,proof=self.prepare()
  broker=SessionCapabilityBroker(self.path,self.registry,"north",self.replicas,2,self.enrolled,
   "authority",self.issuer.public_key().public_bytes_raw().hex(),"broker-a",execution_witness=Down())
  self.assertEqual(broker.execute(self.request,self.attestations(),cap,proof,challenge),"DENIED")
  with sqlite3.connect(self.path) as db:
   self.assertEqual(db.execute("SELECT COUNT(*) FROM session_effects").fetchone()[0],0)
 def test_witness_consumed_then_local_failure_strands_operation(self):
  cap,challenge,proof=self.prepare()
  with sqlite3.connect(self.path) as db:
   db.execute("""CREATE TRIGGER reject_effect BEFORE INSERT ON session_effects
       BEGIN SELECT RAISE(ABORT,'injected local effect failure'); END""")
  self.assertEqual(self.broker.execute(self.request,self.attestations(),cap,proof,challenge),"DENIED")
  self.assertIsNotNone(self.witness.lookup(self.request["operation_id"]))
  with sqlite3.connect(self.path) as db:
   db.execute("DROP TRIGGER reject_effect")
  self.assertEqual(self.broker.execute(self.request,self.attestations(),cap,proof,challenge),"DENIED")
