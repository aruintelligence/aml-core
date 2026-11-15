"""Strict authenticated synthetic-origin observer (separate process).

No witness receipt is issued unless pinned provider signature and replay
ledger both accept the event. The legacy unsigned lab is not used here.
"""
import argparse
import hashlib
import json
import pathlib
import sys
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from origin_event import OriginVerifier
from signed_receipt import issue, key_id, canonical

MAX_BYTES = 8192

def unique_pairs(pairs):
    result = {}
    for k, v in pairs:
        if k in result:
            raise ValueError("duplicate JSON key")
        result[k] = v
    return result

def load_json(path):
    raw = pathlib.Path(path).read_bytes()
    if len(raw) > MAX_BYTES:
        raise ValueError("oversized event")
    return json.loads(raw, object_pairs_hook=unique_pairs,
        parse_constant=lambda _: (_ for _ in ()).throw(ValueError("nonfinite")))

def observe(event_path, pin_path, ledger_path, provider_id):
    # Pin file is separately provisioned. Never trust a public key embedded
    # in an untrusted provider event.
    pin_raw = pathlib.Path(pin_path).read_text(encoding="ascii").strip()
    if len(pin_raw) != 64:
        raise ValueError("invalid pinned key")
    pinned = Ed25519PublicKey.from_public_bytes(bytes.fromhex(pin_raw))
    envelope = load_json(event_path)
    verifier = OriginVerifier(ledger_path, {provider_id: pinned})
    result = verifier.accept(envelope)
    if result != "AUTHENTICATED_SYNTHETIC_EVENT":
        raise ValueError("origin rejected: " + result)
    event = envelope["event"]
    effect_hash = hashlib.sha256(canonical(event["synthetic_effect"])).hexdigest()
    observer_key = Ed25519PrivateKey.generate()
    observer_public = observer_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)
    receipt = issue(observer_key, "witness", event["operation_id"],
        event["request_sha256"], "OBSERVED_SYNTHETIC_EFFECT", effect_hash)
    return {"receipt": receipt, "observer_public_key_hex": observer_public.hex(),
        "observer_key_id": key_id(observer_key.public_key()),
        "provider_key_id": key_id(pinned), "origin_verdict": result,
        "source": "pinned_signed_synthetic_provider_artifact",
        "independent_source_proven": False}

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--event", required=True)
    parser.add_argument("--provider-public-key-file", required=True)
    parser.add_argument("--replay-db", required=True)
    parser.add_argument("--provider-id", required=True)
    args = parser.parse_args()
    try:
        print(json.dumps(observe(args.event, args.provider_public_key_file,
            args.replay_db, args.provider_id), sort_keys=True))
    except (ValueError, OSError, TypeError, json.JSONDecodeError) as exc:
        print("authenticated observer rejected: " + str(exc), file=sys.stderr)
        sys.exit(2)
