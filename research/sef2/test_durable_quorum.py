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
from verify_quorum import verify_with_quorum
from durable_checkpoint_witness import DurableWitness
from signed_history import SignedHistory,digest
from trust_enrollment import propose

def public_hex(key):
    return key.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw).hex()

class DurableQuorumTests(unittest.TestCase):
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
        self.history_db=self.root/"history.sqlite"
        self.history=SignedHistory(str(self.history_db),self.approver.public_key())
        self.assertEqual(self.history.append(propose(self.approver,1,bundle["public_keys"])),"ENROLLED")
        self.checkpoint=self.history.checkpoint()
        self.checkpoint_path=self.root/"checkpoint.json"
        self.checkpoint_path.write_text(json.dumps(self.checkpoint))
        self.pin=digest(self.checkpoint)
        self.privates={name:Ed25519PrivateKey.generate() for name in ("north","south","east")}
        self.keys_path=self.root/"keys.json"
        self.keys_path.write_text(json.dumps({n:public_hex(k) for n,k in self.privates.items()}))
        self.witnesses={name:DurableWitness(self.root/(name+".sqlite"),name,k)
                        for name,k in self.privates.items()}
        self.receipts=[]
        for name in ("north","south"):
            status,receipt=self.witnesses[name].publish(self.checkpoint)
            self.assertEqual(status,"PUBLISHED")
            self.receipts.append(receipt)
        self.attestations=self.root/"attestations.json"
        self.save()

    def save(self):
        self.attestations.write_text(json.dumps(self.receipts))

    def check(self,threshold=2):
        return verify_with_quorum(self.root,self.manifest_path,self.manifest_pin,
            self.history_db,public_hex(self.approver),self.checkpoint_path,
            self.pin,1,self.keys_path,self.attestations,threshold)

    def test_durable_quorum_accepts(self):
        self.assertTrue(self.check())

    def test_witness_restart_retains_checkpoint(self):
        new=DurableWitness(self.root/"north.sqlite","north",self.privates["north"])
        self.assertEqual(new.latest(),self.receipts[0])

    def test_replay_is_idempotent(self):
        status,receipt=self.witnesses["north"].publish(self.checkpoint)
        self.assertEqual(status,"REPLAY")
        self.assertEqual(receipt,self.receipts[0])

    def test_rollback_rejected(self):
        later=dict(self.checkpoint,epoch=2,count=2,head_hash="a"*64)
        self.assertEqual(self.witnesses["north"].publish(later)[0],"PUBLISHED")
        self.assertEqual(self.witnesses["north"].publish(self.checkpoint)[0],"STALE_HISTORY")

    def test_same_epoch_fork_rejected(self):
        fork=dict(self.checkpoint,head_hash="b"*64)
        self.assertEqual(self.witnesses["north"].publish(fork)[0],"FORK_DETECTED")

    def test_one_witness_insufficient(self):
        self.receipts=self.receipts[:1]
        self.save()
        self.assertFalse(self.check())

    def test_forged_signature_rejected(self):
        self.receipts[0]["signature"]="00"*64
        self.save()
        self.assertFalse(self.check())

    def test_unpinned_witness_rejected(self):
        self.receipts[0]["payload"]["witness_id"]="outsider"
        self.save()
        self.assertFalse(self.check())

    def test_conflicting_attestation_rejected(self):
        fork=dict(self.checkpoint,head_hash="b"*64)
        from checkpoint_council import publish
        self.receipts[1]=publish(self.privates["south"],"south",fork)
        self.save()
        self.assertFalse(self.check())

    def test_history_rollback_rejected_end_to_end(self):
        with sqlite3.connect(self.history_db) as con:
            con.execute("DELETE FROM signed_epochs")
        self.assertFalse(self.check())

    def test_wrong_quorum_threshold_rejected(self):
        self.assertFalse(self.check(threshold=3))

    def test_duplicate_witness_rejected(self):
        self.receipts[1]=self.receipts[0]
        self.save()
        self.assertFalse(self.check())

    def test_missing_witness_key_pin_rejected(self):
        self.keys_path.unlink()
        self.assertFalse(self.check())

    def test_tampered_bundle_rejected(self):
        bundle=json.loads((self.root/"bundle.json").read_text())
        bundle["synthetic_only"]=False
        (self.root/"bundle.json").write_text(json.dumps(bundle))
        self.assertFalse(self.check())
