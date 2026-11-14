import json
import pathlib
import sqlite3
import tempfile
import unittest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from durable_checkpoint_witness import DurableWitness

def cp(epoch=1,head="a"*64):
    return {"schema":"AML-SEF2-SIGNED-HISTORY-CHECKPOINT-V1","epoch":epoch,
        "head_hash":head,"count":epoch,"approver_key_id":"c"*64}

class DurableIntegrityTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.db=str(pathlib.Path(self.temp.name)/"witness.sqlite")
        self.key=Ed25519PrivateKey.generate()
        self.store=DurableWitness(self.db,"north",self.key)
        self.assertEqual(self.store.publish(cp())[0],"PUBLISHED")
    def restart(self):
        return DurableWitness(self.db,"north",self.key)
    def test_restart_preserves_verified_checkpoint(self):
        self.assertEqual(self.restart().latest(),self.store.latest())
    def test_retained_epoch_corruption_rejected(self):
        with sqlite3.connect(self.db) as con:
            con.execute("UPDATE retained SET epoch=0")
        with self.assertRaises(ValueError):
            self.restart().latest()
        self.assertEqual(self.restart().publish(cp(2,"b"*64))[0],"CORRUPT_STATE")
    def test_retained_head_corruption_rejected(self):
        with sqlite3.connect(self.db) as con:
            con.execute("UPDATE retained SET head=?",("f"*64,))
        with self.assertRaises(ValueError):
            self.restart().latest()
    def test_checkpoint_payload_corruption_rejected(self):
        with sqlite3.connect(self.db) as con:
            con.execute("UPDATE checkpoints SET payload=?",(json.dumps(cp(1,"b"*64)),))
        with self.assertRaises(ValueError):
            self.restart().latest()
    def test_persisted_signature_corruption_rejected(self):
        envelope=self.store.latest()
        envelope["signature"]="00"*64
        with sqlite3.connect(self.db) as con:
            con.execute("UPDATE checkpoints SET envelope=?",(json.dumps(envelope),))
        with self.assertRaises(ValueError):
            self.restart().latest()
    def test_deleted_retained_state_rejected(self):
        with sqlite3.connect(self.db) as con:
            con.execute("DELETE FROM retained")
        with self.assertRaises(ValueError):
            self.restart().latest()
    def test_same_epoch_changed_count_is_fork(self):
        altered=cp()
        altered["count"]=2
        self.assertEqual(self.restart().publish(altered)[0],"FORK_DETECTED")
