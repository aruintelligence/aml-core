import hashlib
import json
import pathlib
import sys
import tempfile
import unittest
ROOT=pathlib.Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT/"evaluation_kit"))
from enterprise_demo import run
from verify_trusted import verify_trusted
from signed_receipt import canonical

def digest(v):
    return hashlib.sha256(canonical(v)).hexdigest()

class PinnedTrustTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root=pathlib.Path(self.tmp.name)
        run(self.root)
        bundle=json.loads((self.root/"bundle.json").read_text())
        report=json.loads((self.root/"report.json").read_text())
        self.manifest={"schema":"AML-SEF2-TRUST-MANIFEST-V1",
            "public_keys":bundle["public_keys"],"bundle_sha256":digest(bundle),
            "report_sha256":digest(report)}
        self.path=self.root/"trust-manifest.json"
        self.write()
        self.pin=digest(self.manifest)

    def write(self):
        self.path.write_text(json.dumps(self.manifest,sort_keys=True))

    def test_good_external_pin(self):
        self.assertTrue(verify_trusted(self.root,self.path,self.pin))

    def test_missing_pin_rejected(self):
        self.assertFalse(verify_trusted(self.root,self.path,""))

    def test_wrong_pin_rejected(self):
        self.assertFalse(verify_trusted(self.root,self.path,"0"*64))

    def test_substituted_witness_root_rejected(self):
        self.manifest["public_keys"]["witness"]=self.manifest["public_keys"]["provider"]
        self.write()
        self.assertFalse(verify_trusted(self.root,self.path,self.pin))

    def test_replacement_report_rejected(self):
        report=json.loads((self.root/"report.json").read_text())
        report["negative_controls"]["replay_rejected"]=False
        (self.root/"report.json").write_text(json.dumps(report))
        self.assertFalse(verify_trusted(self.root,self.path,self.pin))

    def test_replacement_bundle_rejected(self):
        bundle=json.loads((self.root/"bundle.json").read_text())
        bundle["public_keys"]["witness"]=bundle["public_keys"]["provider"]
        (self.root/"bundle.json").write_text(json.dumps(bundle))
        self.assertFalse(verify_trusted(self.root,self.path,self.pin))

    def test_forged_manifest_and_self_chosen_hash_rejected_by_original_pin(self):
        self.manifest["public_keys"]["provider"]=self.manifest["public_keys"]["witness"]
        self.write()
        self.assertNotEqual(digest(self.manifest),self.pin)
        self.assertFalse(verify_trusted(self.root,self.path,self.pin))

    def test_duplicate_manifest_keys_rejected(self):
        self.path.write_text('{"schema":"x","schema":"y"}')
        self.assertFalse(verify_trusted(self.root,self.path,self.pin))

    def test_report_digest_mismatch_rejected(self):
        self.manifest["report_sha256"]="0"*64
        self.write()
        self.assertFalse(verify_trusted(self.root,self.path,self.pin))

    def test_missing_manifest_rejected(self):
        self.path.unlink()
        self.assertFalse(verify_trusted(self.root,self.path,self.pin))
