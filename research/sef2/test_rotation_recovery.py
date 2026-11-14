"""Independent evaluator pin registry and interrupted-rotation recovery tests."""
import json
import pathlib
import tempfile
import unittest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from durable_checkpoint_witness import DurableWitness
from external_witness_anchor import issue_anchor,anchor_pin,verify_anchor
from pin_registry import PinRegistry
from rotation_recovery import stage,recover
from anchor_rotation import activate_prepared_rotation

def cp(epoch):
    return {"schema":"AML-SEF2-SIGNED-HISTORY-CHECKPOINT-V1","epoch":epoch,
        "head_hash":format(epoch,"064x"),"count":epoch,"approver_key_id":"c"*64}

class RegistryRecoveryTests(unittest.TestCase):
    def setUp(self):
        tmp=tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root=pathlib.Path(tmp.name)
        self.key=Ed25519PrivateKey.generate()
        self.db=self.root/"witness.sqlite"
        self.store=DurableWitness(self.db,"north",self.key)
        self.assertEqual(self.store.publish(cp(1))[0],"PUBLISHED")
        self.anchor=self.root/"active.json"
        initial=issue_anchor(self.store)
        self.anchor.write_text(json.dumps(initial))
        self.old=anchor_pin(initial)
        self.registry_path=self.root/"independent-evaluator.sqlite"
        self.registry=PinRegistry(self.registry_path)
        self.registry.enroll("north",self.old)
        self.candidate=self.root/"candidate.json"
        self.assertEqual(self.store.publish(cp(2))[0],"PUBLISHED")
    def test_registry_rejects_stale_transition(self):
        with self.assertRaises(ValueError):
            self.registry.prepare("north","0"*64,"1"*64)
        self.assertEqual(self.registry.state("north")["active"],self.old)
    def test_crash_after_stage_recovers(self):
        new=stage(self.store,self.anchor,self.candidate,self.registry)
        self.registry=PinRegistry(self.registry_path)
        self.assertEqual(self.registry.state("north")["pending"],new)
        self.assertEqual(recover(self.store,self.anchor,self.candidate,self.registry),"RECOVERED")
        self.assertEqual(self.registry.state("north")["active"],new)
        self.assertEqual(self.registry.state("north")["generation"],1)
    def test_crash_after_activation_before_pin_commit_recovers(self):
        new=stage(self.store,self.anchor,self.candidate,self.registry)
        activate_prepared_rotation(self.anchor,self.candidate,self.old,new)
        self.registry=PinRegistry(self.registry_path)
        self.assertEqual(recover(self.store,self.anchor,self.candidate,self.registry),"RECOVERED")
        self.assertEqual(self.registry.state("north")["active"],new)
    def test_missing_candidate_fails_closed(self):
        stage(self.store,self.anchor,self.candidate,self.registry)
        self.candidate.unlink()
        self.assertEqual(recover(self.store,self.anchor,self.candidate,self.registry),"FAIL_CLOSED")
        self.assertEqual(self.registry.state("north")["active"],self.old)
    def test_rolled_back_witness_fails_closed(self):
        stage(self.store,self.anchor,self.candidate,self.registry)
        self.assertEqual(self.store.publish(cp(3))[0],"PUBLISHED")
        self.assertEqual(recover(self.store,self.anchor,self.candidate,self.registry),"FAIL_CLOSED")
        self.assertIsNotNone(self.registry.state("north")["pending"])
    def test_registry_rejects_duplicate_enrollment(self):
        with self.assertRaises(ValueError):
            self.registry.enroll("north",self.old)

    def test_concurrent_stage_attempt_rejected(self):
        first=stage(self.store,self.anchor,self.candidate,self.registry)
        with self.assertRaises(ValueError):
            stage(self.store,self.anchor,self.root/"second.json",PinRegistry(self.registry_path))
        self.assertEqual(self.registry.state("north")["pending"],first)
        self.assertFalse((self.root/"second.json").exists())

    def test_rollback_of_evaluator_registry_is_detected_by_new_anchor(self):
        import sqlite3
        snapshot=self.root/"registry-snapshot.sqlite"
        with sqlite3.connect(self.registry_path) as src:
            with sqlite3.connect(snapshot) as dst:
                src.backup(dst)
        new=stage(self.store,self.anchor,self.candidate,self.registry)
        self.assertEqual(recover(self.store,self.anchor,self.candidate,self.registry),"RECOVERED")
        with sqlite3.connect(snapshot) as src:
            with sqlite3.connect(self.registry_path) as dst:
                src.backup(dst)
        self.assertEqual(recover(self.store,self.anchor,self.candidate,PinRegistry(self.registry_path)),"FAIL_CLOSED")
        self.assertEqual(anchor_pin(json.loads(self.anchor.read_text())),new)

    def test_prepared_candidate_tamper_fails_closed(self):
        stage(self.store,self.anchor,self.candidate,self.registry)
        self.candidate.write_text("{}")
        self.assertEqual(recover(self.store,self.anchor,self.candidate,self.registry),"FAIL_CLOSED")
        self.assertEqual(self.registry.state("north")["generation"],0)

    def test_restart_after_completed_rotation_is_idempotent(self):
        new=stage(self.store,self.anchor,self.candidate,self.registry)
        self.assertEqual(recover(self.store,self.anchor,self.candidate,self.registry),"RECOVERED")
        self.assertEqual(recover(self.store,self.anchor,self.candidate,PinRegistry(self.registry_path)),"ACTIVE")
        self.assertEqual(self.registry.state("north")["active"],new)
        self.assertEqual(self.registry.state("north")["generation"],1)
