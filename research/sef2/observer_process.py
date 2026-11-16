"""Separate OS process observing a synthetic provider event artifact.

The observer independently computes the event digest and signs a claim with
its own ephemeral Ed25519 key. The artifact itself is NOT independently sourced.
"""
import argparse
import hashlib
import json
import pathlib
import sys
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
from signed_receipt import issue, key_id, canonical

MAX_EVENT = 8192
FIELDS = {"operation_id", "request_sha256", "synthetic_effect"}

def observe(path):
    raw = pathlib.Path(path).read_bytes()
    if len(raw) > MAX_EVENT:
        raise ValueError("oversized event")
    def unique(pairs):
        d = {}
        for k, v in pairs:
            if k in d:
                raise ValueError("duplicate event key")
            d[k] = v
        return d
    event = json.loads(raw, object_pairs_hook=unique,
        parse_constant=lambda _: (_ for _ in ()).throw(ValueError("nonfinite")))
    if type(event) is not dict or set(event) != FIELDS:
        raise ValueError("invalid event schema")
    op, digest, effect = (event[k] for k in ("operation_id", "request_sha256", "synthetic_effect"))
    if type(op) is not str or not op or len(op) > 128:
        raise ValueError("invalid operation")
    if type(digest) is not str or len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
        raise ValueError("invalid digest")
    if type(effect) is not dict or set(effect) != {"effect_id", "kind"}:
        raise ValueError("invalid effect schema")
    if type(effect["effect_id"]) is not str or not effect["effect_id"] or len(effect["effect_id"]) > 128:
        raise ValueError("invalid effect id")
    if effect["kind"] != "synthetic-only" or type(effect["kind"]) is not str:
        raise ValueError("not synthetic")
    effect_hash = hashlib.sha256(canonical(effect)).hexdigest()
    key = Ed25519PrivateKey.generate()
    pub = key.public_key().public_bytes(encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw)
    receipt = issue(key, "witness", op, digest, "OBSERVED_SYNTHETIC_EFFECT", effect_hash)
    return {"observer_public_key_hex": pub.hex(), "observer_key_id": key_id(key.public_key()),
        "receipt": receipt, "source": "local_synthetic_artifact",
        "independent_source_proven": False}

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--event", required=True)
    args = parser.parse_args()
    try:
        print(json.dumps(observe(args.event), sort_keys=True))
    except (ValueError, OSError, json.JSONDecodeError) as exc:
        print("observer rejected event: " + str(exc), file=sys.stderr)
        sys.exit(2)
