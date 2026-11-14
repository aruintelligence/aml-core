import hashlib
import json
import os
import pathlib
import subprocess
import sys
import tempfile
import unittest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from signed_receipt import canonical, issue, key_id
from evidence_gate import adjudicate

class ObserverProcessTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.event_path = pathlib.Path(self.tmp.name) / "event.json"
        self.effect = {"effect_id": "fixture-effect-1", "kind": "synthetic-only"}
        self.event = {"operation_id": "fixture-op-1", "request_sha256": "a"*64,
            "synthetic_effect": self.effect}
        self.write()
        self.auth_key = Ed25519PrivateKey.generate()
        self.provider_key = Ed25519PrivateKey.generate()
        evidence = hashlib.sha256(canonical(self.effect)).hexdigest()
        self.auth = issue(self.auth_key, "authority", "fixture-op-1", "a"*64,
            "CONSUMED", "0"*64)
        self.provider = issue(self.provider_key, "provider", "fixture-op-1", "a"*64,
            "PROVIDER_REPORTED", evidence)

    def write(self):
        self.event_path.write_text(json.dumps(self.event))

    def run_observer(self):
        return subprocess.run([sys.executable, str(pathlib.Path(__file__).with_name("observer_process.py")),
            "--event", str(self.event_path)], capture_output=True, text=True, timeout=10)

    def adjudication(self, output):
        data = json.loads(output)
        pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(data["observer_public_key_hex"]))
        self.assertEqual(data["observer_key_id"], key_id(pub))
        self.assertFalse(data["independent_source_proven"])
        trust = {"authority": {key_id(self.auth_key.public_key()): self.auth_key.public_key()},
            "provider": {key_id(self.provider_key.public_key()): self.provider_key.public_key()},
            "witness": {key_id(pub): pub}}
        return adjudicate(self.auth, self.provider, data["receipt"], trust)

    def test_separate_process_signed_observation(self):
        p = self.run_observer()
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(self.adjudication(p.stdout), "THREE_SIGNED_CONSISTENT_CLAIMS")

    def test_mutated_artifact_conflicts_with_provider(self):
        self.event["synthetic_effect"]["effect_id"] = "tampered"
        self.write()
        p = self.run_observer()
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(self.adjudication(p.stdout), "EVIDENCE_CONFLICT")

    def test_mismatched_operation_rejected_by_gate(self):
        self.event["operation_id"] = "different-op"
        self.write()
        p = self.run_observer()
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(self.adjudication(p.stdout), "EVIDENCE_CONFLICT")

    def test_duplicate_json_key_rejected(self):
        self.event_path.write_text('{"operation_id":"a","operation_id":"b"}')
        self.assertEqual(self.run_observer().returncode, 2)

    def test_non_synthetic_event_rejected(self):
        self.event["synthetic_effect"]["kind"] = "payment"
        self.write()
        self.assertEqual(self.run_observer().returncode, 2)

    def test_missing_event_rejected(self):
        self.event_path.unlink()
        self.assertEqual(self.run_observer().returncode, 2)

    def test_oversized_event_rejected(self):
        self.event_path.write_bytes(b"x" * 8193)
        self.assertEqual(self.run_observer().returncode, 2)

    def test_observer_key_is_distinct_from_provider_key(self):
        p = self.run_observer()
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertNotEqual(json.loads(p.stdout)["observer_key_id"], key_id(self.provider_key.public_key()))
