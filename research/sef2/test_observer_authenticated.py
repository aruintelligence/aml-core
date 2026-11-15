import hashlib
import json
import pathlib
import subprocess
import sys
import tempfile
import unittest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from origin_event import issue_origin
from signed_receipt import issue, key_id, canonical
from evidence_gate import adjudicate

class AuthenticatedObserverIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = pathlib.Path(self.temp.name)
        self.path = root / "event.json"
        self.pin = root / "provider.pin"
        self.db = root / "replay.sqlite"
        self.key = Ed25519PrivateKey.generate()
        self.authority_key = Ed25519PrivateKey.generate()
        self.effect = {"effect_id": "synthetic-effect-1", "kind": "synthetic-only"}
        self.pin.write_text(self.key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw).hex())
        self.envelope = self.make_event()
        self.write()

    def make_event(self, key=None, seq=1, op="op-1", effect=None):
        return issue_origin(key or self.key, "provider-a", seq, op,
            "a"*64, self.effect if effect is None else effect)

    def write(self):
        self.path.write_text(json.dumps(self.envelope))

    def run_observer(self):
        return subprocess.run([sys.executable,
            str(pathlib.Path(__file__).with_name("observer_authenticated.py")),
            "--event", str(self.path), "--provider-public-key-file", str(self.pin),
            "--replay-db", str(self.db), "--provider-id", "provider-a"],
            capture_output=True, text=True, timeout=10)

    def test_end_to_end_signed_origin_and_three_party_gate(self):
        proc = self.run_observer()
        self.assertEqual(proc.returncode, 0, proc.stderr)
        result = json.loads(proc.stdout)
        self.assertEqual(result["origin_verdict"], "AUTHENTICATED_SYNTHETIC_EVENT")
        self.assertFalse(result["independent_source_proven"])
        witness_pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(result["observer_public_key_hex"]))
        trust = {"authority": {key_id(self.authority_key.public_key()): self.authority_key.public_key()},
            "provider": {key_id(self.key.public_key()): self.key.public_key()},
            "witness": {key_id(witness_pub): witness_pub}}
        auth = issue(self.authority_key, "authority", "op-1", "a"*64, "CONSUMED", "0"*64)
        provider = issue(self.key, "provider", "op-1", "a"*64, "PROVIDER_REPORTED",
            hashlib.sha256(canonical(self.effect)).hexdigest())
        self.assertEqual(adjudicate(auth, provider, result["receipt"], trust),
            "THREE_SIGNED_CONSISTENT_CLAIMS")

    def test_replay_after_process_restart_denied(self):
        self.assertEqual(self.run_observer().returncode, 0)
        retry = self.run_observer()
        self.assertEqual(retry.returncode, 2)
        self.assertEqual(retry.stdout, "")
        self.assertIn("REPLAY_OR_DUPLICATE", retry.stderr)

    def test_unsigned_artifact_denied(self):
        self.path.write_text(json.dumps(self.envelope["event"]))
        self.assertEqual(self.run_observer().returncode, 2)

    def test_key_substitution_denied(self):
        self.envelope = self.make_event(key=Ed25519PrivateKey.generate())
        self.write()
        self.assertEqual(self.run_observer().returncode, 2)

    def test_signed_payload_tamper_denied(self):
        self.envelope["event"]["synthetic_effect"]["effect_id"] = "changed"
        self.write()
        self.assertEqual(self.run_observer().returncode, 2)

    def test_missing_pin_denied(self):
        self.pin.unlink()
        self.assertEqual(self.run_observer().returncode, 2)

    def test_duplicate_json_keys_denied(self):
        self.path.write_text('{"event":{},"event":{},"signature":"x"}')
        self.assertEqual(self.run_observer().returncode, 2)

    def test_same_operation_new_sequence_denied(self):
        self.assertEqual(self.run_observer().returncode, 0)
        self.envelope = self.make_event(seq=2)
        self.write()
        self.assertEqual(self.run_observer().returncode, 2)

    def test_same_sequence_new_operation_denied(self):
        self.assertEqual(self.run_observer().returncode, 0)
        self.envelope = self.make_event(op="op-2")
        self.write()
        self.assertEqual(self.run_observer().returncode, 2)

    def test_invalid_non_synthetic_effect_denied(self):
        with self.assertRaises(ValueError):
            self.make_event(effect={"effect_id": "bad", "kind": "payment"})
