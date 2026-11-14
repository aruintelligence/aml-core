"""Independent pinned anchor catches consistent witness DB snapshot rollback."""
import json
import pathlib
import sqlite3
import tempfile
import unittest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from durable_checkpoint_witness import DurableWitness
from external_witness_anchor import issue_anchor,anchor_pin,verify_anchor
from anchor_rotation import rotate_anchor,prepare_rotation,activate_prepared_rotation

def cp(epoch,head):
    return {"schema":"AML-SEF2-SIGNED-HISTORY-CHECKPOINT-V1","epoch":epoch,
        "head_hash":head,"count":epoch,"approver_key_id":"c"*64}

class ExternalAnchorTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root=pathlib.Path(self.tmp.name)
        self.db=self.root/"witness.sqlite"
        self.snapshot=self.root/"snapshot.sqlite"
        self.key=Ed25519PrivateKey.generate()
        self.pub=self.key.public_key().public_bytes_raw().hex()
        self.store=DurableWitness(self.db,"north",self.key)
        self.assertEqual(self.store.publish(cp(1,"a"*64))[0],"PUBLISHED")
        with sqlite3.connect(self.db) as con:
            with sqlite3.connect(self.snapshot) as backup:
                con.backup(backup)
        self.assertEqual(self.store.publish(cp(2,"b"*64))[0],"PUBLISHED")
        self.anchor=issue_anchor(self.store)
        self.anchor_file=self.root/"external-anchor.json"
        self.anchor_file.write_text(json.dumps(self.anchor,sort_keys=True))
        self.pin=anchor_pin(self.anchor)

    def check(self):
        return verify_anchor(self.db,"north",self.pub,self.anchor_file,self.pin)

    def test_current_checkpoint_accepted(self):
        self.assertTrue(self.check())

    def test_restart_uses_independent_pin(self):
        self.assertIsNotNone(DurableWitness(self.db,"north",self.key).latest())
        self.assertTrue(self.check())

    def test_consistent_snapshot_rollback_rejected(self):
        with sqlite3.connect(self.snapshot) as source:
            with sqlite3.connect(self.db) as dest:
                source.backup(dest)
        self.assertFalse(self.check())
        self.assertEqual(DurableWitness(self.db,"north",self.key).latest()["payload"]["checkpoint"]["epoch"],1)

    def test_modified_anchor_rejected(self):
        self.anchor["checkpoint"]["epoch"]=1
        self.anchor_file.write_text(json.dumps(self.anchor))
        self.assertFalse(self.check())

    def test_wrong_pin_rejected(self):
        self.assertFalse(verify_anchor(self.db,"north",self.pub,self.anchor_file,"0"*64))

    def test_wrong_public_key_rejected(self):
        wrong=Ed25519PrivateKey.generate().public_key().public_bytes_raw().hex()
        self.assertFalse(verify_anchor(self.db,"north",wrong,self.anchor_file,self.pin))

    def test_local_head_tamper_rejected(self):
        with sqlite3.connect(self.db) as con:
            con.execute("UPDATE retained SET head=?",("f"*64,))
        self.assertFalse(self.check())

    def test_missing_external_anchor_rejected(self):
        self.anchor_file.unlink()
        self.assertFalse(self.check())

    def test_atomic_rotation_accepts_new_independent_pin(self):
        old=self.pin
        self.assertEqual(self.store.publish(cp(3,"d"*64))[0],"PUBLISHED")
        new=rotate_anchor(self.store,self.anchor_file,old)
        self.assertNotEqual(old,new)
        self.assertFalse(verify_anchor(self.db,"north",self.pub,self.anchor_file,old))
        self.assertTrue(verify_anchor(self.db,"north",self.pub,self.anchor_file,new))

    def test_rotation_rejects_untrusted_predecessor(self):
        self.assertEqual(self.store.publish(cp(3,"d"*64))[0],"PUBLISHED")
        with self.assertRaises(ValueError):
            rotate_anchor(self.store,self.anchor_file,"0"*64)
        self.assertEqual(anchor_pin(json.loads(self.anchor_file.read_text())),self.pin)

    def test_rotation_rejects_same_epoch(self):
        with self.assertRaises(ValueError):
            rotate_anchor(self.store,self.anchor_file,self.pin)

    def test_rollback_after_rotation_fails_with_new_pin(self):
        self.assertEqual(self.store.publish(cp(3,"d"*64))[0],"PUBLISHED")
        new=rotate_anchor(self.store,self.anchor_file,self.pin)
        with sqlite3.connect(self.snapshot) as source:
            with sqlite3.connect(self.db) as dest:
                source.backup(dest)
        self.assertFalse(verify_anchor(self.db,"north",self.pub,self.anchor_file,new))

    def test_prepared_rotation_keeps_old_anchor_active(self):
        self.assertEqual(self.store.publish(cp(3,"d"*64))[0],"PUBLISHED")
        candidate=self.root/"candidate.json"
        new=prepare_rotation(self.store,self.anchor_file,self.pin,candidate)
        self.assertNotEqual(new,self.pin)
        self.assertEqual(anchor_pin(json.loads(self.anchor_file.read_text())),self.pin)
        self.assertEqual(anchor_pin(json.loads(candidate.read_text())),new)

    def test_prepared_rotation_requires_approved_pin(self):
        self.assertEqual(self.store.publish(cp(3,"d"*64))[0],"PUBLISHED")
        candidate=self.root/"candidate.json"
        new=prepare_rotation(self.store,self.anchor_file,self.pin,candidate)
        with self.assertRaises(ValueError):
            activate_prepared_rotation(self.anchor_file,candidate,self.pin,"0"*64)
        self.assertTrue(candidate.exists())
        self.assertEqual(anchor_pin(json.loads(self.anchor_file.read_text())),self.pin)
        self.assertEqual(activate_prepared_rotation(self.anchor_file,candidate,self.pin,new),new)
        self.assertTrue(verify_anchor(self.db,"north",self.pub,self.anchor_file,new))

    def test_prepared_rotation_restart_recovery(self):
        self.assertEqual(self.store.publish(cp(3,"d"*64))[0],"PUBLISHED")
        candidate=self.root/"candidate.json"
        new=prepare_rotation(self.store,self.anchor_file,self.pin,candidate)
        restarted=DurableWitness(self.db,"north",self.key)
        self.assertEqual(restarted.latest()["payload"]["checkpoint"]["epoch"],3)
        self.assertEqual(activate_prepared_rotation(self.anchor_file,candidate,self.pin,new),new)
        self.assertTrue(verify_anchor(self.db,"north",self.pub,self.anchor_file,new))

    def test_prepared_rotation_rejects_stale_old_pin(self):
        self.assertEqual(self.store.publish(cp(3,"d"*64))[0],"PUBLISHED")
        candidate=self.root/"candidate.json"
        new=prepare_rotation(self.store,self.anchor_file,self.pin,candidate)
        with self.assertRaises(ValueError):
            activate_prepared_rotation(self.anchor_file,candidate,"0"*64,new)
        self.assertEqual(anchor_pin(json.loads(self.anchor_file.read_text())),self.pin)
