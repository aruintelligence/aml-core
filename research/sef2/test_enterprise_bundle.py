import json
import pathlib
import sys
import tempfile
import unittest
ROOT = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "evaluation_kit"))
from enterprise_demo import run
from verify_bundle import verify_bundle

class EnterpriseBundleTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = pathlib.Path(self.tmp.name)

    def test_one_command_bundle_verifies(self):
        report = run(self.root)
        self.assertEqual(report["three_party_verdict"], "THREE_SIGNED_CONSISTENT_CLAIMS")
        self.assertTrue(verify_bundle(self.root))

    def test_public_bundle_detects_receipt_mutation(self):
        run(self.root)
        path = self.root / "bundle.json"
        bundle = json.loads(path.read_text())
        bundle["witness_receipt"]["payload"]["state"] = "FORGED"
        path.write_text(json.dumps(bundle))
        self.assertFalse(verify_bundle(self.root))

    def test_public_bundle_detects_provider_event_mutation(self):
        run(self.root)
        path = self.root / "bundle.json"
        bundle = json.loads(path.read_text())
        bundle["origin_event"]["event"]["synthetic_effect"]["effect_id"] = "changed"
        path.write_text(json.dumps(bundle))
        self.assertFalse(verify_bundle(self.root))

    def test_public_bundle_detects_key_substitution(self):
        run(self.root)
        path = self.root / "bundle.json"
        bundle = json.loads(path.read_text())
        bundle["public_keys"]["witness"] = bundle["public_keys"]["provider"]
        path.write_text(json.dumps(bundle))
        self.assertFalse(verify_bundle(self.root))

    def test_report_tampering_rejected(self):
        run(self.root)
        path = self.root / "report.json"
        report = json.loads(path.read_text())
        report["external_execution_proven"] = True
        path.write_text(json.dumps(report))
        self.assertFalse(verify_bundle(self.root))

    def test_no_private_keys_in_public_bundle(self):
        run(self.root)
        bundle = json.loads((self.root / "bundle.json").read_text())
        self.assertEqual(set(bundle), {"schema", "synthetic_only", "public_keys",
            "origin_event", "authority_receipt", "provider_receipt", "witness_receipt"})

    def test_all_negative_controls_pass(self):
        report = run(self.root)
        self.assertTrue(all(report["negative_controls"].values()))

    def test_no_real_world_claims(self):
        report = run(self.root)
        self.assertFalse(report["external_execution_proven"])
        self.assertFalse(report["independent_source_proven"])
        self.assertFalse(report["replay_db_rollback_resistant"])
