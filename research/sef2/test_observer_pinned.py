import json
import pathlib
import subprocess
import sys
import tempfile
import unittest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from origin_event import issue_origin
from signed_receipt import key_id, verify

def raw_private(key):
    return key.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
        serialization.NoEncryption()).hex()

def raw_public(key):
    return key.public_key().public_bytes(serialization.Encoding.Raw,
        serialization.PublicFormat.Raw).hex()

class PinnedWitnessIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = pathlib.Path(self.tmp.name)
        self.event = root / "event.json"
        self.provider_pin = root / "provider.pin"
        self.witness_pin = root / "witness.pin"
        self.witness_secret = root / "witness.secret"
        self.ledger = root / "ledger.sqlite"
        self.provider = Ed25519PrivateKey.generate()
        self.witness = Ed25519PrivateKey.generate()
        self.provider_pin.write_text(raw_public(self.provider))
        self.witness_pin.write_text(raw_public(self.witness))
        self.witness_secret.write_text(raw_private(self.witness))
        self.write_event()

    def write_event(self, sequence=1, op="op-1"):
        self.event.write_text(json.dumps(issue_origin(self.provider, "provider-a", sequence,
            op, "a"*64, {"effect_id": "effect-1", "kind": "synthetic-only"})))

    def run_observer(self):
        return subprocess.run([sys.executable,
            str(pathlib.Path(__file__).with_name("observer_pinned.py")),
            "--event", str(self.event), "--provider-public-key-file", str(self.provider_pin),
            "--replay-db", str(self.ledger), "--provider-id", "provider-a",
            "--witness-private-key-file", str(self.witness_secret),
            "--witness-public-key-file", str(self.witness_pin)],
            capture_output=True, text=True, timeout=10)

    def test_signed_observation_verifies_under_external_witness_pin(self):
        p = self.run_observer()
        self.assertEqual(p.returncode, 0, p.stderr)
        r = json.loads(p.stdout)
        self.assertTrue(verify(r["receipt"], "witness", {"witness": {
            key_id(self.witness.public_key()): self.witness.public_key()}}))
        self.assertFalse(r["external_execution_proven"])

    def test_witness_key_substitution_denied(self):
        self.witness_secret.write_text(raw_private(Ed25519PrivateKey.generate()))
        self.assertEqual(self.run_observer().returncode, 2)

    def test_witness_pin_substitution_denied(self):
        self.witness_pin.write_text(raw_public(Ed25519PrivateKey.generate()))
        self.assertEqual(self.run_observer().returncode, 2)

    def test_provider_pin_substitution_denied(self):
        self.provider_pin.write_text(raw_public(Ed25519PrivateKey.generate()))
        self.assertEqual(self.run_observer().returncode, 2)

    def test_missing_witness_secret_denied(self):
        self.witness_secret.unlink()
        self.assertEqual(self.run_observer().returncode, 2)

    def test_provider_cannot_be_witness_identity(self):
        self.witness_secret.write_text(raw_private(self.provider))
        self.witness_pin.write_text(raw_public(self.provider))
        self.assertEqual(self.run_observer().returncode, 2)

    def test_replay_after_restart_denied(self):
        self.assertEqual(self.run_observer().returncode, 0)
        self.assertEqual(self.run_observer().returncode, 2)

    def test_persistent_witness_identity_across_processes(self):
        self.assertEqual(self.run_observer().returncode, 0)
        self.write_event(sequence=2, op="op-2")
        p = self.run_observer()
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(json.loads(p.stdout)["witness_key_id"], key_id(self.witness.public_key()))

    def test_tampered_origin_denied_before_witness_signing(self):
        envelope = json.loads(self.event.read_text())
        envelope["event"]["synthetic_effect"]["effect_id"] = "tampered"
        self.event.write_text(json.dumps(envelope))
        p = self.run_observer()
        self.assertEqual(p.returncode, 2)
        self.assertEqual(p.stdout, "")
