"""Independent offline verification using ONLY public keys and bundle/report."""
import argparse
import hashlib
import json
import pathlib
import sys
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from signed_receipt import canonical, key_id
from evidence_gate import adjudicate
from origin_event import DOMAIN, valid_event
from cryptography.exceptions import InvalidSignature

def verify_bundle(directory):
    root = pathlib.Path(directory)
    bundle = json.loads((root / "bundle.json").read_text())
    report = json.loads((root / "report.json").read_text())
    if bundle.get("schema") != "AML-SEF2-EVALUATION-BUNDLE-V1":
        return False
    if report.get("bundle_sha256") != hashlib.sha256(canonical(bundle)).hexdigest():
        return False
    keys = {}
    for role in ("authority", "provider", "witness"):
        key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(bundle["public_keys"][role]))
        keys[role] = {key_id(key): key}
    origin = bundle["origin_event"]
    event = origin["event"]
    if not valid_event(event) or set(origin) != {"event", "signature"}:
        return False
    try:
        next(iter(keys["provider"].values())).verify(bytes.fromhex(origin["signature"]),
            DOMAIN + canonical(event))
    except (InvalidSignature, ValueError):
        return False
    evidence = hashlib.sha256(canonical(event["synthetic_effect"])).hexdigest()
    if (bundle["witness_receipt"]["payload"]["evidence_sha256"] != evidence
        or bundle["provider_receipt"]["payload"]["evidence_sha256"] != evidence
        or bundle["witness_receipt"]["payload"]["operation_id"] != event["operation_id"]
        or bundle["witness_receipt"]["payload"]["request_sha256"] != event["request_sha256"]):
        return False
    verdict = adjudicate(bundle["authority_receipt"], bundle["provider_receipt"],
        bundle["witness_receipt"], keys)
    return (verdict == report.get("three_party_verdict") == "THREE_SIGNED_CONSISTENT_CLAIMS"
        and report.get("external_execution_proven") is False
        and report.get("independent_source_proven") is False
        and report.get("replay_db_rollback_resistant") is False
        and all(report.get("negative_controls", {}).values()))

if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--input", required=True)
    args = p.parse_args()
    try:
        good = verify_bundle(args.input)
    except (ValueError, KeyError, TypeError, OSError, json.JSONDecodeError):
        good = False
    print("PUBLIC_BUNDLE_VERIFIED" if good else "BUNDLE_REJECTED")
    sys.exit(0 if good else 2)
