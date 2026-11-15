import copy,pathlib,sqlite3,tempfile,unittest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from authenticated_execution_challenge import make_execution_challenge
from execution_gate_receipt import evaluate_and_issue
from external_effect_coordinator import ExternalEffectCoordinator
from idempotent_effect_endpoint import IdempotentEffectEndpoint,verify_endpoint_receipt
from pin_registry import PinRegistry
from pin_replication import PinReplica
from replica_attestation import attest
from session_capability import issue_session_capability,make_holder_proof
from session_epoch_anchor import SessionEpochAnchor

class DirectTransport:
 def __init__(self,endpoint): self.endpoint=endpoint
 def apply(self,*args): return self.endpoint.apply(*args)
 def query(self,*args): return self.endpoint.query(*args)

class DropAfterCommit:
 def __init__(self,endpoint): self.endpoint=endpoint
 def apply(self,*args):
  self.endpoint.apply(*args)
  raise OSError("response lost after downstream commit")
 def query(self,*args): return self.endpoint.query(*args)

class DropBeforeCommit:
 def __init__(self,endpoint,query_down=False): self.endpoint=endpoint; self.query_down=query_down
 def apply(self,*args): raise OSError("request lost before downstream commit")
 def query(self,*args):
  if self.query_down: raise OSError("status unavailable")
  return self.endpoint.query(*args)

class CommitThenStatusDown:
 def __init__(self,endpoint): self.endpoint=endpoint
 def apply(self,*args):
  self.endpoint.apply(*args)
  raise OSError("commit response lost")
 def query(self,*args): raise OSError("status unavailable")

class ForgedReceiptTransport:
 def __init__(self,endpoint): self.endpoint=endpoint
 def apply(self,*args):
  receipt=self.endpoint.apply(*args)
  receipt=copy.deepcopy(receipt); receipt["signature"]="00"*64
  return receipt
 def query(self,*args): return None

class ExternalEffectCoordinatorTests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup); root=pathlib.Path(self.tmp.name)
  self.registry=PinRegistry(root/"registry.sqlite"); self.registry.enroll("north","a"*64)
  self.replicas=[PinReplica(root/(f"r{i}.sqlite")) for i in range(3)]
  self.replica_keys=[Ed25519PrivateKey.generate() for _ in range(3)]
  self.enrolled={f"r{i}":k.public_key().public_bytes_raw().hex() for i,k in enumerate(self.replica_keys)}
  for r in self.replicas:r.record("north",0,"a"*64)
  self.authority=Ed25519PrivateKey.generate(); self.broker=Ed25519PrivateKey.generate()
  self.holder=Ed25519PrivateKey.generate(); self.evaluator=Ed25519PrivateKey.generate()
  self.endpoint_key=Ed25519PrivateKey.generate()
  self.endpoint=IdempotentEffectEndpoint(root/"endpoint.sqlite","endpoint-1",self.endpoint_key)
  self.anchor=SessionEpochAnchor(root/"epoch.sqlite"); self.anchor.initialize("broker-a",0)
  self.request={"operation_id":"external-effect-op","action":"payment:simulate",
   "target":"fixture:merchant-a","amount_cents":100}
  self.cap=issue_session_capability(self.authority,"authority","broker-a",self.request,0,
   self.holder.public_key().public_bytes_raw().hex())
  self.challenge=make_execution_challenge(self.broker,"broker-external","broker-a",
   self.request,self.cap,0,"c"*64)
  self.proof=make_holder_proof(self.holder,self.cap,self.request,"c"*64)
  attestations=[attest(r,f"r{i}","north",self.replica_keys[i]) for i,r in enumerate(self.replicas)]
  self.eval=evaluate_and_issue(self.registry,"north",self.replicas,2,attestations,self.enrolled,
   self.evaluator,"evaluator-external","broker-a",self.request,self.cap,self.challenge,0)
  self.db=root/"coordinator.sqlite"
  self.coordinator=self.make(DirectTransport(self.endpoint))
 def make(self,transport):
  return ExternalEffectCoordinator(self.db,"authority",self.authority.public_key().public_bytes_raw().hex(),
   "broker-a","broker-external",self.broker.public_key().public_bytes_raw().hex(),
   "evaluator-external",self.evaluator.public_key().public_bytes_raw().hex(),"north",self.anchor,
   "endpoint-1",self.endpoint_key.public_key().public_bytes_raw().hex(),transport)
 def execute(self,cap=None,challenge=None,proof=None,evaluator=None,request=None):
  return self.coordinator.execute(request or self.request,cap or self.cap,challenge or self.challenge,
   proof or self.proof,evaluator or self.eval)
 def status(self):
  with sqlite3.connect(self.db) as db:
   return db.execute("SELECT status FROM external_effects WHERE operation_id=?",
    (self.request["operation_id"],)).fetchone()[0]

 def test_idempotent_endpoint_returns_same_signed_receipt(self):
  request_hash="a"*64; effect_hash="b"*64
  first=self.endpoint.apply("same-op",request_hash,effect_hash)
  second=self.endpoint.apply("same-op",request_hash,effect_hash)
  self.assertEqual(first,second)
  self.assertTrue(verify_endpoint_receipt(first,self.endpoint_key.public_key().public_bytes_raw().hex(),
   "endpoint-1","same-op",request_hash,effect_hash))
  with self.assertRaises(PermissionError): self.endpoint.apply("same-op","c"*64,effect_hash)

 def test_normal_remote_effect_commits_once(self):
  self.assertEqual(self.execute(),"APPLIED")
  self.assertEqual(self.execute(),"ALREADY_APPLIED")
  self.assertEqual(self.status(),"COMMITTED")
  self.assertIsNotNone(self.endpoint.query(self.request["operation_id"]))

 def test_lost_response_after_remote_commit_is_reconciled_in_same_call(self):
  self.coordinator=self.make(DropAfterCommit(self.endpoint))
  self.assertEqual(self.execute(),"APPLIED")
  self.assertEqual(self.status(),"COMMITTED")

 def test_commit_then_status_outage_returns_ambiguous_not_success(self):
  self.coordinator=self.make(CommitThenStatusDown(self.endpoint))
  self.assertEqual(self.execute(),"AMBIGUOUS")
  self.assertEqual(self.status(),"PENDING")
  self.coordinator=self.make(DirectTransport(self.endpoint))
  self.assertEqual(self.coordinator.reconcile_pending(self.request["operation_id"]),"RECOVERED")
  self.assertEqual(self.status(),"COMMITTED")

 def test_request_lost_before_remote_commit_returns_ambiguous_then_completes(self):
  self.coordinator=self.make(DropBeforeCommit(self.endpoint,query_down=True))
  self.assertEqual(self.execute(),"AMBIGUOUS")
  self.assertIsNone(self.endpoint.query(self.request["operation_id"]))
  self.coordinator=self.make(DirectTransport(self.endpoint))
  self.assertEqual(self.coordinator.reconcile_pending(self.request["operation_id"]),"RECOVERED")
  self.assertIsNotNone(self.endpoint.query(self.request["operation_id"]))

 def test_revocation_after_pending_does_not_cancel_already_authorized_remote_effect(self):
  self.coordinator=self.make(DropBeforeCommit(self.endpoint,query_down=True))
  self.assertEqual(self.execute(),"AMBIGUOUS")
  self.assertTrue(self.anchor.compare_and_set("broker-a",0,1))
  self.coordinator=self.make(DirectTransport(self.endpoint))
  self.assertEqual(self.coordinator.reconcile_pending(self.request["operation_id"]),"RECOVERED")

 def test_revocation_before_pending_blocks_remote_effect(self):
  self.assertTrue(self.anchor.compare_and_set("broker-a",0,1))
  self.assertEqual(self.execute(),"DENIED")
  self.assertIsNone(self.endpoint.query(self.request["operation_id"]))

 def test_forged_endpoint_receipt_never_reports_success(self):
  self.coordinator=self.make(ForgedReceiptTransport(self.endpoint))
  self.assertEqual(self.execute(),"DENIED")
  self.assertEqual(self.status(),"PENDING")
  self.coordinator=self.make(DirectTransport(self.endpoint))
  self.assertEqual(self.coordinator.reconcile_pending(self.request["operation_id"]),"RECOVERED")

 def test_conflicting_remote_idempotency_binding_fails_closed(self):
  self.endpoint.apply(self.request["operation_id"],"f"*64,"e"*64)
  self.assertEqual(self.execute(),"DENIED")
  self.assertEqual(self.status(),"PENDING")

 def test_forged_authorization_never_reaches_endpoint(self):
  cap=copy.deepcopy(self.cap); cap["signature"]="00"*64
  self.assertEqual(self.execute(cap=cap),"DENIED")
  self.assertIsNone(self.endpoint.query(self.request["operation_id"]))

 def test_pending_operation_with_different_evidence_cannot_be_rebound(self):
  self.coordinator=self.make(DropBeforeCommit(self.endpoint,query_down=True))
  self.assertEqual(self.execute(),"AMBIGUOUS")
  changed=dict(self.request,amount_cents=101)
  changed_cap=issue_session_capability(self.authority,"authority","broker-a",changed,0,
   self.holder.public_key().public_bytes_raw().hex())
  changed_challenge=make_execution_challenge(self.broker,"broker-external","broker-a",
   changed,changed_cap,0,"d"*64)
  changed_proof=make_holder_proof(self.holder,changed_cap,changed,"d"*64)
  attestations=[attest(r,f"r{i}","north",self.replica_keys[i]) for i,r in enumerate(self.replicas)]
  changed_eval=evaluate_and_issue(self.registry,"north",self.replicas,2,attestations,self.enrolled,
   self.evaluator,"evaluator-external","broker-a",changed,changed_cap,changed_challenge,0)
  self.coordinator=self.make(DirectTransport(self.endpoint))
  self.assertEqual(self.coordinator.execute(changed,changed_cap,changed_challenge,
   changed_proof,changed_eval),"DENIED")
