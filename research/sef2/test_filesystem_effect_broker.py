import pathlib,sqlite3,tempfile,unittest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pin_registry import PinRegistry
from pin_replication import PinReplica
from replica_attestation import attest
from session_capability import issue_session_capability,make_holder_proof
from filesystem_effect_broker import DurableFilesystemEffectBroker,InjectedEffectCrash

class FilesystemEffectBrokerTests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
  root=pathlib.Path(self.tmp.name)
  self.registry=PinRegistry(root/"evaluator.sqlite"); self.registry.enroll("north","a"*64)
  self.replicas=[PinReplica(root/(f"r{i}.sqlite")) for i in range(3)]
  self.replica_keys=[Ed25519PrivateKey.generate() for _ in range(3)]
  self.enrolled={f"r{i}":k.public_key().public_bytes_raw().hex() for i,k in enumerate(self.replica_keys)}
  for r in self.replicas:r.record("north",0,"a"*64)
  self.issuer=Ed25519PrivateKey.generate(); self.holder=Ed25519PrivateKey.generate()
  self.db=root/"broker.sqlite"; self.effects=root/"protected-effects"
  self.request={"operation_id":"file-op","action":"payment:simulate","target":"fixture:merchant-a","amount_cents":100}
  self.broker=self.make_broker()
 def make_broker(self,fault=None):
  return DurableFilesystemEffectBroker(self.db,self.effects,self.registry,"north",self.replicas,2,
   self.enrolled,"authority",self.issuer.public_key().public_bytes_raw().hex(),"broker-a",
   fault_hook=fault)
 def signed(self):
  return [attest(r,f"r{i}","north",self.replica_keys[i]) for i,r in enumerate(self.replicas)]
 def cap(self,request=None):
  request=request or self.request
  return issue_session_capability(self.issuer,"authority","broker-a",request,self.broker.current_epoch(),
   self.holder.public_key().public_bytes_raw().hex())
 def auth(self,request=None):
  request=request or self.request; cap=self.cap(request)
  challenge=self.broker.issue_execution_challenge(request["operation_id"])
  proof=make_holder_proof(self.holder,cap,request,challenge)
  return cap,challenge,proof
 def effect_path(self,request=None):
  return self.broker._effect_path((request or self.request)["operation_id"])
 def test_authorized_session_creates_real_protected_file_once(self):
  cap,ch,proof=self.auth()
  self.assertEqual(self.broker.execute(self.request,self.signed(),cap,proof,ch),"APPLIED")
  self.assertTrue(self.effect_path().is_file())
  self.assertEqual(self.broker.execute(self.request,self.signed(),cap,proof,ch),"ALREADY_APPLIED")
 def test_missing_capability_cannot_create_file(self):
  ch=self.broker.issue_execution_challenge(self.request["operation_id"])
  self.assertEqual(self.broker.execute(self.request,self.signed(),None,None,ch),"DENIED")
  self.assertFalse(self.effect_path().exists())
 def test_revoked_capability_cannot_start_effect(self):
  cap,ch,proof=self.auth(); self.broker.revoke_all()
  self.assertEqual(self.broker.execute(self.request,self.signed(),cap,proof,ch),"DENIED")
  self.assertFalse(self.effect_path().exists())
 def test_crash_after_pending_is_recoverable_without_reauthorizing_new_action(self):
  def fault(point):
   if point=="after_pending": raise InjectedEffectCrash(point)
  self.broker=self.make_broker(fault); cap,ch,proof=self.auth()
  with self.assertRaises(InjectedEffectCrash):
   self.broker.execute(self.request,self.signed(),cap,proof,ch)
  self.assertFalse(self.effect_path().exists())
  with sqlite3.connect(self.db) as db:
   self.assertEqual(db.execute("SELECT status FROM filesystem_effects").fetchone()[0],"PENDING")
  restarted=self.make_broker()
  self.assertEqual(restarted.recover_pending(self.request["operation_id"]),"RECOVERED")
  self.assertTrue(self.effect_path().exists())
 def test_crash_after_durable_effect_before_db_commit_reconciles(self):
  def fault(point):
   if point=="after_effect": raise InjectedEffectCrash(point)
  self.broker=self.make_broker(fault); cap,ch,proof=self.auth()
  with self.assertRaises(InjectedEffectCrash):
   self.broker.execute(self.request,self.signed(),cap,proof,ch)
  self.assertTrue(self.effect_path().exists())
  with sqlite3.connect(self.db) as db:
   self.assertEqual(db.execute("SELECT status FROM filesystem_effects").fetchone()[0],"PENDING")
  restarted=self.make_broker()
  self.assertEqual(restarted.recover_pending(self.request["operation_id"]),"RECOVERED")
 def test_pending_authorization_can_finish_after_later_revocation(self):
  def fault(point):
   if point=="after_pending": raise InjectedEffectCrash(point)
  self.broker=self.make_broker(fault); cap,ch,proof=self.auth()
  with self.assertRaises(InjectedEffectCrash):
   self.broker.execute(self.request,self.signed(),cap,proof,ch)
  self.broker=self.make_broker(); self.broker.revoke_all()
  self.assertEqual(self.broker.recover_pending(self.request["operation_id"]),"RECOVERED")
  self.assertTrue(self.effect_path().exists())
 def test_conflicting_request_for_pending_operation_denied(self):
  def fault(point):
   if point=="after_pending": raise InjectedEffectCrash(point)
  self.broker=self.make_broker(fault); cap,ch,proof=self.auth()
  with self.assertRaises(InjectedEffectCrash):
   self.broker.execute(self.request,self.signed(),cap,proof,ch)
  changed=dict(self.request,amount_cents=101)
  self.broker=self.make_broker(); cap2=self.cap(changed)
  proof2=make_holder_proof(self.holder,cap2,changed,ch)
  self.assertEqual(self.broker.execute(changed,self.signed(),cap2,proof2,ch),"DENIED")
 def test_tampered_committed_effect_fails_closed(self):
  cap,ch,proof=self.auth()
  self.assertEqual(self.broker.execute(self.request,self.signed(),cap,proof,ch),"APPLIED")
  self.effect_path().write_text("tampered")
  self.assertEqual(self.broker.execute(self.request,self.signed(),cap,proof,ch),"DENIED")
 def test_effect_directory_is_private(self):
  self.assertEqual(self.effects.stat().st_mode & 0o077,0)
