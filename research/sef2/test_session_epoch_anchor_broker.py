import pathlib,shutil,sqlite3,tempfile,unittest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pin_registry import PinRegistry
from pin_replication import PinReplica
from replica_attestation import attest
from session_capability import issue_session_capability,make_holder_proof
from session_capability_broker import SessionCapabilityBroker
from session_epoch_anchor import SessionEpochAnchor

class SessionEpochRollbackTests(unittest.TestCase):
 def setUp(self):
  t=tempfile.TemporaryDirectory(); self.addCleanup(t.cleanup); self.root=pathlib.Path(t.name)
  self.registry=PinRegistry(self.root/"eval.sqlite"); self.registry.enroll("north","a"*64)
  self.replicas=[PinReplica(self.root/f"r{i}.sqlite") for i in range(3)]
  self.replica_keys=[Ed25519PrivateKey.generate() for _ in range(3)]
  self.enrolled={f"r{i}":k.public_key().public_bytes_raw().hex() for i,k in enumerate(self.replica_keys)}
  for replica in self.replicas: replica.record("north",0,"a"*64)
  self.issuer=Ed25519PrivateKey.generate(); self.holder=Ed25519PrivateKey.generate()
  self.path=self.root/"broker.sqlite"; self.anchor=SessionEpochAnchor(self.root/"epoch-anchor.sqlite")
  self.broker=self.new_broker()
  self.request={"operation_id":"rollback-session","action":"payment:simulate","target":"fixture:merchant-a","amount_cents":100}
 def new_broker(self):
  return SessionCapabilityBroker(self.path,self.registry,"north",self.replicas,2,self.enrolled,
   "authority",self.issuer.public_key().public_bytes_raw().hex(),"broker-a",epoch_anchor=self.anchor)
 def attestations(self):
  return [attest(r,f"r{i}","north",self.replica_keys[i]) for i,r in enumerate(self.replicas)]
 def capability(self,epoch=None):
  return issue_session_capability(self.issuer,"authority","broker-a",self.request,
   self.broker.current_epoch() if epoch is None else epoch,self.holder.public_key().public_bytes_raw().hex())
 def test_broker_database_rollback_cannot_resurrect_revoked_capability(self):
  cap=self.capability(); challenge=self.broker.issue_execution_challenge(self.request["operation_id"])
  proof=make_holder_proof(self.holder,cap,self.request,challenge)
  snapshot=self.root/"broker-before-revoke.sqlite"; shutil.copy2(self.path,snapshot)
  self.assertEqual(self.broker.revoke_all(),1)
  self.assertEqual(self.anchor.read_epoch("broker-a"),1)
  shutil.copy2(snapshot,self.path)
  restarted=self.new_broker()
  self.assertEqual(restarted.current_epoch(),1)
  self.assertEqual(restarted.execute(self.request,self.attestations(),cap,proof,challenge),"DENIED")
 def test_anchor_ahead_reconciles_local_epoch_only_toward_less_authority(self):
  self.assertTrue(self.anchor.compare_and_set("broker-a",0,1))
  self.assertEqual(self.broker.current_epoch(),1)
  with sqlite3.connect(self.path) as db:
   self.assertEqual(db.execute("SELECT epoch FROM session_policy_epoch WHERE audience='broker-a'").fetchone()[0],1)
 def test_anchor_behind_local_state_fails_closed(self):
  with sqlite3.connect(self.path) as db:
   db.execute("UPDATE session_policy_epoch SET epoch=1 WHERE audience='broker-a'")
  with self.assertRaises(PermissionError): self.broker.current_epoch()
  cap=issue_session_capability(self.issuer,"authority","broker-a",self.request,1,self.holder.public_key().public_bytes_raw().hex())
  self.assertEqual(self.broker.execute(self.request,self.attestations(),cap,None,"x"*64),"DENIED")
 def test_reconciliation_can_complete_interrupted_monotonic_revocation(self):
  with sqlite3.connect(self.path) as db:
   db.execute("UPDATE session_policy_epoch SET epoch=1 WHERE audience='broker-a'")
  self.assertEqual(self.broker.reconcile_revocation_anchor(),1)
  self.assertEqual(self.anchor.read_epoch("broker-a"),1)
 def test_restart_refuses_local_epoch_ahead_of_anchor(self):
  with sqlite3.connect(self.path) as db:
   db.execute("UPDATE session_policy_epoch SET epoch=1 WHERE audience='broker-a'")
  with self.assertRaises(ValueError): self.new_broker()
