"""One-command offline synthetic witness evaluation with externally checkable receipts."""
import argparse
import hashlib
import json
import pathlib
import subprocess
import sys
import tempfile
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from origin_event import issue_origin
from signed_receipt import canonical, issue, key_id, verify
from evidence_gate import adjudicate

def public_hex(key):
    return key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()

def private_hex(key):
    return key.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
        serialization.NoEncryption()).hex()

def run(output):
    output = pathlib.Path(output)
    output.mkdir(parents=True, exist_ok=True)
    provider, witness, authority = (Ed25519PrivateKey.generate() for _ in range(3))
    effect = {"effect_id": "synthetic-effect-001", "kind": "synthetic-only"}
    op, request_hash = "synthetic-operation-001", "a"*64
    event = issue_origin(provider, "fixture-provider", 1, op, request_hash, effect)
    with tempfile.TemporaryDirectory() as temp:
        root = pathlib.Path(temp)
        event_path, provider_pin, witness_pin, witness_secret, ledger = (
            root / n for n in ("event.json", "provider.pin", "witness.pin",
                              "witness.secret", "ledger.sqlite"))
        event_path.write_text(json.dumps(event))
        provider_pin.write_text(public_hex(provider))
        witness_pin.write_text(public_hex(witness))
        witness_secret.write_text(private_hex(witness))
        command = [sys.executable, str(ROOT / "observer_pinned.py"),
            "--event", str(event_path), "--provider-public-key-file", str(provider_pin),
            "--replay-db", str(ledger), "--provider-id", "fixture-provider",
            "--witness-private-key-file", str(witness_secret),
            "--witness-public-key-file", str(witness_pin)]
        first = subprocess.run(command, capture_output=True, text=True, timeout=15)
        if first.returncode:
            raise RuntimeError("observer failed: " + first.stderr)
        observed = json.loads(first.stdout)
        replay = subprocess.run(command, capture_output=True, text=True, timeout=15)
        witness_receipt = observed["receipt"]
        evidence_hash = hashlib.sha256(canonical(effect)).hexdigest()
        authority_receipt = issue(authority, "authority", op, request_hash, "CONSUMED", "0"*64)
        provider_receipt = issue(provider, "provider", op, request_hash, "PROVIDER_REPORTED", evidence_hash)
        keys = {role: {key_id(key.public_key()): key.public_key()}
                for role, key in (("authority", authority), ("provider", provider), ("witness", witness))}
        verdict = adjudicate(authority_receipt, provider_receipt, witness_receipt, keys)
        tampered = json.loads(json.dumps(witness_receipt))
        tampered["payload"]["state"] = "FORGED"
        controls = {"replay_rejected": replay.returncode == 2 and not replay.stdout
                    and "REPLAY_OR_DUPLICATE" in replay.stderr,
            "tampered_witness_rejected": not verify(tampered, "witness", keys),
            "missing_witness_rejected": adjudicate(authority_receipt, provider_receipt, None, keys)
                == "MISSING_INDEPENDENT_EVIDENCE",
            "substituted_witness_key_rejected": not verify(witness_receipt, "witness",
                {"witness": {key_id(Ed25519PrivateKey.generate().public_key()):
                    Ed25519PrivateKey.generate().public_key()}})}
        if verdict != "THREE_SIGNED_CONSISTENT_CLAIMS" or not all(controls.values()):
            raise AssertionError("synthetic evaluation failed")
        bundle = {"schema": "AML-SEF2-EVALUATION-BUNDLE-V1", "synthetic_only": True,
            "public_keys": {role: public_hex(key) for role, key in
                (("authority", authority), ("provider", provider), ("witness", witness))},
            "origin_event": event, "authority_receipt": authority_receipt,
            "provider_receipt": provider_receipt, "witness_receipt": witness_receipt}
        report = {"schema": "AML-SEF2-EVALUATION-REPORT-V1",
            "three_party_verdict": verdict, "negative_controls": controls,
            "persistent_pinned_witness": observed["persistent_witness_identity"],
            "independent_source_proven": False, "external_execution_proven": False,
            "replay_db_rollback_resistant": False,
            "bundle_sha256": hashlib.sha256(canonical(bundle)).hexdigest()}
        (output / "bundle.json").write_text(json.dumps(bundle, sort_keys=True, indent=2) + "\n")
        (output / "report.json").write_text(json.dumps(report, sort_keys=True, indent=2) + "\n")
        return report

if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--output", default="sef2-evaluation-output")
    args = p.parse_args()
    print(json.dumps(run(args.output), sort_keys=True, indent=2))
