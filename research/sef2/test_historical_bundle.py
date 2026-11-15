import json
import pathlib
import sqlite3
import sys
import tempfile
import unittest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
ROOT=pathlib.Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT/"evaluation_kit"))
from enterprise_demo import run
from verify_trusted import sha
from verify_historical import verify_historical
from signed_history import SignedHistory,digest
from trust_enrollment import propose

def public_hex(key):
    return key.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw).hex()

class HistoricalBundleTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root=pathlib.Path(self.tmp.name)
        run(self.root)
        bundle=json.loads((self.root/"bundle.json").read_text())
        report=json.loads((self.root/"report.json").read_text())
        self.manifest={"schema":"AML-SEF2-TRUST-MANIFEST-V1",
            "public_keys":bundle["public_keys"],"bundle_sha256":sha(bundle),
            "report_sha256":sha(report)}
        self.manifest_path=self.root/"manifest.json"
        self.manifest_path.write_text(json.dumps(self.manifest))
        self.manifest_pin=sha(self.manifest)
        self.approver=Ed25519PrivateKey.generate()
        self.db=self.root/"history.sqlite"
        self.history=SignedHistory(str(self.db),self.approver.public_key())
        self.assertEqual(self.history.append(propose(self.approver,1,bundle["public_keys"])),"ENROLLED")
        self.checkpoint_path=self.root/"checkpoint.json"
        self.checkpoint=self.history.checkpoint()
        self.checkpoint_path.write_text(json.dumps(self.checkpoint))
        self.pin=digest(self.checkpoint)

    def check(self,epoch=1,pin=None,approver=None):
        return verify_historical(self.root,self.manifest_path,self.manifest_pin,
            self.db,public_hex(approver or self.approver),self.checkpoint_path,
            self.pin if pin is None else pin,epoch)

    def test_complete_history_accepted(self):
        self.assertTrue(self.check())

    def test_wrong_approver_rejected(self):
        self.assertFalse(self.check(approver=Ed25519PrivateKey.generate()))

    def test_missing_checkpoint_pin_rejected(self):
        self.assertFalse(self.check(pin=""))

    def test_wrong_epoch_rejected(self):
        self.assertFalse(self.check(epoch=2))

    def test_history_deleted_rollback_rejected(self):
        with sqlite3.connect(self.db) as con:
            con.execute("DELETE FROM signed_epochs")
        self.assertFalse(self.check())

    def test_signed_envelope_tampering_rejected(self):
        with sqlite3.connect(self.db) as con:
            envelope=json.loads(con.execute("SELECT envelope FROM signed_epochs").fetchone()[0])
            envelope["payload"]["epoch"]=7
            con.execute("UPDATE signed_epochs SET envelope=?",(json.dumps(envelope),))
        self.assertFalse(self.check())

    def test_hash_chain_tampering_rejected(self):
        with sqlite3.connect(self.db) as con:
            con.execute("UPDATE signed_epochs SET entry_hash=?",("f"*64,))
        self.assertFalse(self.check())

    def test_competing_fork_rejected(self):
        alternate=self.root/"fork.sqlite"
        fork=SignedHistory(str(alternate),self.approver.public_key())
        keys=dict(self.manifest["public_keys"])
        keys["witness"]=public_hex(Ed25519PrivateKey.generate())
        self.assertEqual(fork.append(propose(self.approver,1,keys)),"ENROLLED")
        self.assertFalse(verify_historical(self.root,self.manifest_path,self.manifest_pin,
            alternate,public_hex(self.approver),self.checkpoint_path,self.pin,1))

    def test_epoch_advance_rejects_stale_checkpoint(self):
        self.assertEqual(self.history.append(propose(self.approver,2,
            self.manifest["public_keys"])),"ENROLLED")
        self.assertFalse(self.check())

    def test_rotated_revoked_witness_rejects_old_bundle(self):
        keys=dict(self.manifest["public_keys"])
        old=keys["witness"]
        keys["witness"]=public_hex(Ed25519PrivateKey.generate())
        self.assertEqual(self.history.append(propose(self.approver,2,keys,[old])),"ENROLLED")
        checkpoint=self.history.checkpoint()
        self.checkpoint_path.write_text(json.dumps(checkpoint))
        self.assertFalse(self.check(epoch=2,pin=digest(checkpoint)))

    def test_report_replacement_rejected(self):
        report=json.loads((self.root/"report.json").read_text())
        report["external_execution_proven"]=True
        (self.root/"report.json").write_text(json.dumps(report))
        self.assertFalse(self.check())

    def test_missing_database_rejected(self):
        self.db.unlink()
        self.assertFalse(self.check())
