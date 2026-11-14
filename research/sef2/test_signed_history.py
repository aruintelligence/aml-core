import json
import pathlib
import sqlite3
import tempfile
import unittest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
from signed_history import SignedHistory,digest
from trust_enrollment import propose

def pub(k):
    return k.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw).hex()

class SignedHistoryTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.db=str(pathlib.Path(self.tmp.name)/"history.sqlite")
        self.approver=Ed25519PrivateKey.generate()
        self.store=SignedHistory(self.db,self.approver.public_key())
        self.keys={r:pub(Ed25519PrivateKey.generate()) for r in ("authority","provider","witness")}
        self.assertEqual(self.store.append(propose(self.approver,1,self.keys)),"ENROLLED")
        self.checkpoint=self.store.checkpoint()
        self.pin=digest(self.checkpoint)

    def test_external_checkpoint_accepted(self):
        self.assertTrue(self.store.verify_checkpoint(self.checkpoint,self.pin))

    def test_restart_verifies_full_history(self):
        self.assertTrue(SignedHistory(self.db,self.approver.public_key()).verify_checkpoint(self.checkpoint,self.pin))

    def test_missing_checkpoint_rejected(self):
        self.assertFalse(self.store.verify_checkpoint(None,self.pin))

    def test_wrong_checkpoint_pin_rejected(self):
        self.assertFalse(self.store.verify_checkpoint(self.checkpoint,"0"*64))

    def test_deleted_history_rollback_detected(self):
        with sqlite3.connect(self.db) as con:
            con.execute("DELETE FROM signed_epochs")
        self.assertFalse(self.store.verify_checkpoint(self.checkpoint,self.pin))

    def test_forged_history_signature_detected(self):
        with sqlite3.connect(self.db) as con:
            row=con.execute("SELECT envelope FROM signed_epochs").fetchone()[0]
            env=json.loads(row)
            env["signature"]="00"*64
            con.execute("UPDATE signed_epochs SET envelope=?",(json.dumps(env),))
        self.assertFalse(self.store.verify_checkpoint(self.checkpoint,self.pin))

    def test_forged_chain_hash_detected(self):
        with sqlite3.connect(self.db) as con:
            con.execute("UPDATE signed_epochs SET entry_hash=?",("f"*64,))
        self.assertFalse(self.store.verify_checkpoint(self.checkpoint,self.pin))

    def test_fork_at_same_epoch_rejected(self):
        changed=dict(self.keys)
        changed["witness"]=pub(Ed25519PrivateKey.generate())
        self.assertEqual(self.store.append(propose(self.approver,1,changed)),"STALE_EPOCH")

    def test_rotation_and_revocation_history(self):
        changed=dict(self.keys)
        changed["witness"]=pub(Ed25519PrivateKey.generate())
        self.assertEqual(self.store.append(propose(self.approver,2,changed,[self.keys["witness"]])),"ENROLLED")
        self.assertIsNotNone(self.store.checkpoint())
        self.assertFalse(self.store.verify_checkpoint(self.checkpoint,self.pin))

    def test_reenroll_revoked_key_rejected(self):
        changed=dict(self.keys)
        changed["witness"]=pub(Ed25519PrivateKey.generate())
        self.store.append(propose(self.approver,2,changed,[self.keys["witness"]]))
        self.assertEqual(self.store.append(propose(self.approver,3,self.keys,[changed["witness"]])),"REVOKED_KEY")

    def test_unknown_approver_rejected(self):
        self.assertEqual(self.store.append(propose(Ed25519PrivateKey.generate(),2,self.keys)),"UNAUTHORIZED")

    def test_old_external_checkpoint_detects_advanced_history(self):
        self.assertEqual(self.store.append(propose(self.approver,2,self.keys)),"ENROLLED")
        self.assertFalse(self.store.verify_checkpoint(self.checkpoint,self.pin))

    def test_competing_valid_fork_detected_by_external_head(self):
        other=str(pathlib.Path(self.tmp.name)/"fork.sqlite")
        fork=SignedHistory(other,self.approver.public_key())
        changed=dict(self.keys)
        changed["witness"]=pub(Ed25519PrivateKey.generate())
        self.assertEqual(fork.append(propose(self.approver,1,changed)),"ENROLLED")
        self.assertFalse(fork.verify_checkpoint(self.checkpoint,self.pin))
