import copy,pathlib,sqlite3,tempfile,unittest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from authenticated_execution_challenge import make_execution_challenge
from execution_gate_receipt import evaluate_and_issue
from pin_registry import PinRegistry
from pin_replication import PinReplica
from replica_attestation import attest
from session_capability import issue_session_capability,make_holder_proof
from session_epoch_anchor import SessionEpochAnchor
from independent_filesystem_effect_executor import (IndependentFilesystemEffectExecutor,
 InjectedIndependentFilesystemCrash)
from authorized_execution_consumption import AuthorizedExecutionConsumptionWitness

class IndependentFilesystemEffectExecutorTests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup); root=pathlib.Path(self.tmp.name)
  self.registry=PinRegistry(root/"registry.sqlite"); self.registry.enroll("north","a"*64)
  self.replicas=[PinReplica(root/(f"r{i}.sqlite")) for i in range(3)]
  self.replica_keys=[Ed25519PrivateKey.generate() for _ in range(3)]
  self.enrolled={f"r{i}":k.public_key().public_bytes_raw().hex() for i,k in enumerate(self.replica_keys)}
  for r in self.replicas:r.record("north",0,"a"*64)
  self.authority=Ed25519PrivateKey.generate(); self.broker=Ed25519PrivateKey.generate()
  self.holder=Ed25519PrivateKey.generate(); self.evaluator=Ed25519PrivateKey.generate()
  self.anchor=SessionEpochAnchor(root/"epoch.sqlite"); self.anchor.initialize("broker-a",0)
  self.request={"operation_id":"independent-real-effect","action":"payment:simulate",
   "target":"fixture:merchant-a","amount_cents":100}
  self.cap=issue_session_capability(self.authority,"authority","broker-a",self.request,0,
   self.holder.public_key().public_bytes_raw().hex())
  self.challenge=make_execution_challenge(self.broker,"broker-instance-real","broker-a",
   self.request,self.cap,0,"c"*64)
  self.proof=make_holder_proof(self.holder,self.cap,self.request,"c"*64)
  attestations=[attest(r,f"r{i}","north",self.replica_keys[i]) for i,r in enumerate(self.replicas)]
  self.eval=evaluate_and_issue(self.registry,"north",self.replicas,2,attestations,self.enrolled,
   self.evaluator,"evaluator-real","broker-a",self.request,self.cap,self.challenge,0)
  self.db=root/"executor.sqlite"; self.effects=root/"effects"
  self.execution_witness=AuthorizedExecutionConsumptionWitness(root/"execution-consumption-v3.sqlite")
  self.executor=self.make()
 def make(self,fault=None):
  return IndependentFilesystemEffectExecutor(self.db,self.effects,"authority",
   self.authority.public_key().public_bytes_raw().hex(),"broker-a","broker-instance-real",
   self.broker.public_key().public_bytes_raw().hex(),"evaluator-real",
   self.evaluator.public_key().public_bytes_raw().hex(),"north",self.anchor,fault,
   self.execution_witness)
 def execute(self,cap=None,challenge=None,proof=None,evaluator=None,request=None):
  return self.executor.execute(request or self.request,cap or self.cap,challenge or self.challenge,
   proof or self.proof,evaluator or self.eval)
 def test_all_independent_evidence_creates_real_file_once(self):
  self.assertEqual(self.execute(),"APPLIED"); self.assertEqual(self.execute(),"ALREADY_APPLIED")
  self.assertEqual(len(list(self.effects.glob("*.effect.json"))),1)
 def test_forged_authority_broker_holder_or_evaluator_evidence_denied(self):
  for field,value in (("cap",copy.deepcopy(self.cap)),("challenge",copy.deepcopy(self.challenge)),
                      ("proof",copy.deepcopy(self.proof)),("evaluator",copy.deepcopy(self.eval))):
   value["signature"]="00"*64
   kwargs={field:value}
   with self.subTest(field=field): self.assertEqual(self.execute(**kwargs),"DENIED")
  self.assertEqual(len(list(self.effects.glob("*.effect.json"))),0)
 def test_revocation_before_pending_blocks_effect(self):
  self.anchor.compare_and_set("broker-a",0,1)
  self.assertEqual(self.execute(),"DENIED"); self.assertFalse(any(self.effects.iterdir()))
 def test_crash_after_pending_reconciles_without_new_authorization(self):
  def fault(point):
   if point=="after_pending": raise InjectedIndependentFilesystemCrash(point)
  self.executor=self.make(fault)
  with self.assertRaises(InjectedIndependentFilesystemCrash): self.execute()
  self.assertFalse(any(self.effects.iterdir()))
  self.executor=self.make()
  self.assertEqual(self.executor.recover_pending(self.request["operation_id"]),"RECOVERED")
 def test_crash_after_file_before_commit_reconciles(self):
  def fault(point):
   if point=="after_effect": raise InjectedIndependentFilesystemCrash(point)
  self.executor=self.make(fault)
  with self.assertRaises(InjectedIndependentFilesystemCrash): self.execute()
  self.assertEqual(len(list(self.effects.glob("*.effect.json"))),1)
  self.executor=self.make()
  self.assertEqual(self.executor.recover_pending(self.request["operation_id"]),"RECOVERED")
 def test_revocation_after_pending_does_not_cancel_already_authorized_operation(self):
  def fault(point):
   if point=="after_pending": raise InjectedIndependentFilesystemCrash(point)
  self.executor=self.make(fault)
  with self.assertRaises(InjectedIndependentFilesystemCrash): self.execute()
  self.anchor.compare_and_set("broker-a",0,1)
  self.executor=self.make()
  self.assertEqual(self.executor.recover_pending(self.request["operation_id"]),"RECOVERED")
 def test_committed_file_tamper_fails_closed(self):
  self.assertEqual(self.execute(),"APPLIED")
  next(self.effects.glob("*.effect.json")).write_text("tampered")
  self.assertEqual(self.execute(),"DENIED")
 def test_effect_directory_is_private(self):
  self.assertEqual(self.effects.stat().st_mode & 0o077,0)

 def test_crash_after_consumption_before_pending_strands_safely(self):
  def fault(point):
   if point=="after_consumption": raise InjectedIndependentFilesystemCrash(point)
  self.executor=self.make(fault)
  with self.assertRaises(InjectedIndependentFilesystemCrash): self.execute()
  self.assertEqual(self.execution_witness.head()["sequence"],1)
  with sqlite3.connect(self.db) as db:
   self.assertEqual(db.execute("SELECT COUNT(*) FROM independent_filesystem_effects").fetchone()[0],0)
  self.assertFalse(any(self.effects.iterdir()))
  self.executor=self.make()
  self.assertEqual(self.execute(),"DENIED")
  self.assertFalse(any(self.effects.iterdir()))

 def test_executor_database_rollback_cannot_reauthorize_real_effect(self):
  import shutil
  snapshot=pathlib.Path(self.tmp.name)/"executor-before.sqlite"; shutil.copy2(self.db,snapshot)
  self.assertEqual(self.execute(),"APPLIED")
  self.assertEqual(self.execution_witness.head()["sequence"],1)
  shutil.copy2(snapshot,self.db)
  self.executor=self.make()
  self.assertEqual(self.execute(),"DENIED")
  self.assertEqual(len(list(self.effects.glob("*.effect.json"))),1)

 def test_coordinated_effect_file_and_executor_db_rollback_cannot_repeat_consumed_effect(self):
  import shutil
  snapshot=pathlib.Path(self.tmp.name)/"executor-before-both.sqlite"; shutil.copy2(self.db,snapshot)
  self.assertEqual(self.execute(),"APPLIED")
  next(self.effects.glob("*.effect.json")).unlink()
  shutil.copy2(snapshot,self.db)
  self.executor=self.make()
  self.assertEqual(self.execute(),"DENIED")
  self.assertFalse(any(self.effects.iterdir()))
