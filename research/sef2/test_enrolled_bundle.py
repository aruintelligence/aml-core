import json
import pathlib
import sys
import tempfile
import unittest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
ROOT=pathlib.Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT/"evaluation_kit"))
from enterprise_demo import run
from verify_trusted import sha
from verify_enrolled import verify_enrolled
from trust_enrollment import Enrollment,propose

class ActiveEnrollmentIntegrationTests(unittest.TestCase):
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
        self.write_manifest()
        self.manifest_pin=sha(self.manifest)
        self.approver=Ed25519PrivateKey.generate()
        self.db=self.root/"enrollment.sqlite"
        self.store=Enrollment(str(self.db),self.approver.public_key())
        self.assertEqual(self.store.accept(propose(self.approver,1,bundle["public_keys"])),"ENROLLED")
        self.state_pin=sha(self.store.manifest())

    def write_manifest(self):
        self.manifest_path.write_text(json.dumps(self.manifest))

    def check(self,epoch=1,pin=None):
        return verify_enrolled(self.root,self.manifest_path,self.manifest_pin,
            str(self.db),epoch,self.state_pin if pin is None else pin)

    def test_active_enrollment_accepted(self):
        self.assertTrue(self.check())

    def test_wrong_active_epoch_rejected(self):
        self.assertFalse(self.check(epoch=2))

    def test_missing_state_pin_rejected(self):
        self.assertFalse(self.check(pin=""))

    def test_wrong_state_pin_rejected(self):
        self.assertFalse(self.check(pin="0"*64))

    def test_unenrolled_bundle_keys_rejected(self):
        self.manifest["public_keys"]["witness"]=self.manifest["public_keys"]["provider"]
        self.write_manifest()
        self.assertFalse(self.check())

    def test_rotated_witness_invalidates_prior_bundle(self):
        old=self.store.manifest()["public_keys"]
        changed=dict(old)
        from cryptography.hazmat.primitives import serialization
        changed["witness"]=Ed25519PrivateKey.generate().public_key().public_bytes(
            serialization.Encoding.Raw,serialization.PublicFormat.Raw).hex()
        self.assertEqual(self.store.accept(propose(self.approver,2,changed,[old["witness"]])),"ENROLLED")
        self.assertFalse(self.check())
        self.assertFalse(self.check(epoch=2,pin=sha(self.store.manifest())))

    def test_revoked_key_cannot_be_active(self):
        with __import__("sqlite3").connect(self.db) as con:
            con.execute("INSERT INTO revoked VALUES (?)",(self.manifest["public_keys"]["witness"],))
        self.assertFalse(self.check())

    def test_missing_enrollment_db_rejected(self):
        self.db.unlink()
        self.assertFalse(self.check())

    def test_bundle_replacement_rejected(self):
        bundle=json.loads((self.root/"bundle.json").read_text())
        bundle["witness_receipt"]["payload"]["state"]="FORGED"
        (self.root/"bundle.json").write_text(json.dumps(bundle))
        self.assertFalse(self.check())

    def test_unsigned_enrollment_attempt_does_not_change_epoch(self):
        forged=propose(Ed25519PrivateKey.generate(),2,self.manifest["public_keys"])
        self.assertEqual(self.store.accept(forged),"UNAUTHORIZED")
        self.assertTrue(self.check())

    def test_old_epoch_pin_rejected_after_new_epoch(self):
        keys=self.store.manifest()["public_keys"]
        self.assertEqual(self.store.accept(propose(self.approver,2,keys)),"ENROLLED")
        self.assertFalse(self.check())

    def test_manifest_replacement_rejected(self):
        self.manifest["report_sha256"]="0"*64
        self.write_manifest()
        self.assertFalse(self.check())
