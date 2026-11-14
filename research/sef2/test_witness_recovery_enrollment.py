import copy,pathlib,tempfile,unittest,concurrent.futures
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from trust_enrollment import Enrollment,propose
from witness_key_recovery import make_transition
from witness_recovery_enrollment import WitnessRecoveryEnrollment
def pub(k): return k.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw).hex()
def cp(e=1,h="a"*64): return {"schema":"AML-SEF2-SIGNED-HISTORY-CHECKPOINT-V1","epoch":e,"head_hash":h,"count":e,"approver_key_id":"c"*64}
class RecoveryEnrollmentIntegrationTests(unittest.TestCase):
 def setUp(self):
  t=tempfile.TemporaryDirectory(); self.addCleanup(t.cleanup); self.path=str(pathlib.Path(t.name)/"trust.sqlite")
  self.approver=Ed25519PrivateKey.generate(); self.root=Ed25519PrivateKey.generate(); self.old=Ed25519PrivateKey.generate(); self.new=Ed25519PrivateKey.generate()
  self.keys={"authority":pub(Ed25519PrivateKey.generate()),"provider":pub(Ed25519PrivateKey.generate()),"witness":pub(self.old)}
  self.enrollment=Enrollment(self.path,self.approver.public_key()); self.enrollment.accept(propose(self.approver,1,self.keys))
  self.recovery_path=str(pathlib.Path(self.tmp.name)/"recovery.sqlite")
  self.coordinator=WitnessRecoveryEnrollment(self.path,self.recovery_path,self.root.public_key(),"offline-root")
  self.state=self.coordinator.initialize("north",cp())
  self.transition=make_transition(self.root,self.new,"north",self.state,cp(2,"b"*64),"offline-root")
 def test_atomic_manifest_update_and_revocation(self):
  self.assertEqual(self.coordinator.recover("north",self.transition),"RECOVERED")
  m=self.enrollment.manifest(); self.assertEqual(m["public_keys"]["witness"],pub(self.new)); self.assertIn(pub(self.old),m["revoked_key_hex"])
  self.assertEqual(self.coordinator.state("north")["generation"],1)
 def test_replay_rejected_after_restart(self):
  self.coordinator.recover("north",self.transition)
  again=WitnessRecoveryEnrollment(self.path,self.recovery_path,self.root.public_key(),"offline-root")
  self.assertEqual(again.recover("north",self.transition),"INVALID_RECOVERY")
 def test_compromised_old_key_not_required(self): self.assertEqual(self.coordinator.recover("north",self.transition),"RECOVERED")
 def test_invalid_signature_no_mutation(self):
  bad=copy.deepcopy(self.transition); bad["recovery_signature"]="00"*64
  self.assertEqual(self.coordinator.recover("north",bad),"INVALID_RECOVERY")
  self.assertEqual(self.enrollment.manifest()["public_keys"]["witness"],pub(self.old)); self.assertEqual(self.coordinator.state("north"),self.state)
 def test_successor_proof_required(self):
  bad=copy.deepcopy(self.transition); bad["proof_of_possession"]="00"*64
  self.assertEqual(self.coordinator.recover("north",bad),"INVALID_RECOVERY")
 def test_wrong_root_rejected(self):
  other=WitnessRecoveryEnrollment(self.path,self.recovery_path,Ed25519PrivateKey.generate().public_key(),"offline-root")
  self.assertEqual(other.recover("north",self.transition),"INVALID_RECOVERY")
 def test_stale_manifest_rejected(self):
  self.enrollment.accept(propose(self.approver,2,{**self.keys,"witness":pub(Ed25519PrivateKey.generate())},[pub(self.old)]))
  self.assertEqual(self.coordinator.recover("north",self.transition),"TRUST_STATE_MISMATCH")
 def test_concurrent_replay_only_one_wins(self):
  with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool: results=list(pool.map(lambda _:self.coordinator.recover("north",self.transition),range(2)))
  self.assertEqual(results.count("RECOVERED"),1); self.assertEqual(results.count("INVALID_RECOVERY"),1)
 def test_uninitialized_witness_fails_closed(self): self.assertEqual(self.coordinator.recover("south",self.transition),"UNINITIALIZED")

 def test_storage_failure_rolls_back_manifest_revocation_and_generation(self):
  import sqlite3
  with sqlite3.connect(self.recovery_path) as con:
   con.execute("""CREATE TRIGGER reject_recovery_event BEFORE INSERT ON witness_recovery_events
    BEGIN SELECT RAISE(ABORT,'injected durable event failure'); END""")
  self.assertEqual(self.coordinator.recover("north",self.transition),"STORE_OR_STATE_ERROR")
  self.assertEqual(self.enrollment.manifest()["epoch"],1)
  self.assertEqual(self.enrollment.manifest()["public_keys"]["witness"],pub(self.old))
  self.assertEqual(self.coordinator.state("north"),self.state)
  with sqlite3.connect(self.recovery_path) as con:
   self.assertEqual(con.execute("SELECT COUNT(*) FROM witness_recovery_events").fetchone()[0],0)

 def test_recovery_state_is_not_co_located_with_trust_manifest(self):
  self.assertNotEqual(pathlib.Path(self.path).resolve(),pathlib.Path(self.recovery_path).resolve())
  self.assertTrue(pathlib.Path(self.recovery_path).is_file())

 def test_constructor_rejects_same_database_for_both_trust_domains(self):
  with self.assertRaises(ValueError):
   WitnessRecoveryEnrollment(self.path,self.path,self.root.public_key(),"offline-root")
