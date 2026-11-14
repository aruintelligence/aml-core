"""Synthetic provider-origin signed event envelope and replay ledger.

Provisioned public key must arrive through an independent trusted channel.
"""
import hashlib
import json
import sqlite3
from cryptography.exceptions import InvalidSignature
from signed_receipt import canonical, key_id

DOMAIN = b"AML-SEF2-ORIGIN-EVENT-V1\x00"
FIELDS = {"version", "provider_id", "sequence", "operation_id", "request_sha256", "synthetic_effect"}

def issue_origin(private_key, provider_id, sequence, operation_id, request_sha256, effect):
    event = {"version": 1, "provider_id": provider_id, "sequence": sequence,
        "operation_id": operation_id, "request_sha256": request_sha256,
        "synthetic_effect": effect}
    if not valid_event(event):
        raise ValueError("invalid origin event")
    return {"event": event, "signature": private_key.sign(DOMAIN + canonical(event)).hex()}

def valid_event(e):
    return (type(e) is dict and set(e) == FIELDS and type(e["version"]) is int
        and e["version"] == 1 and type(e["provider_id"]) is str and 0 < len(e["provider_id"]) <= 128
        and type(e["sequence"]) is int and 0 <= e["sequence"] < 2**63
        and type(e["operation_id"]) is str and 0 < len(e["operation_id"]) <= 128
        and type(e["request_sha256"]) is str and len(e["request_sha256"]) == 64
        and all(c in "0123456789abcdef" for c in e["request_sha256"])
        and type(e["synthetic_effect"]) is dict
        and set(e["synthetic_effect"]) == {"effect_id", "kind"}
        and type(e["synthetic_effect"]["effect_id"]) is str
        and 0 < len(e["synthetic_effect"]["effect_id"]) <= 128
        and type(e["synthetic_effect"]["kind"]) is str
        and e["synthetic_effect"]["kind"] == "synthetic-only")

class OriginVerifier:
    def __init__(self, db_path, pinned_provider_keys):
        self.db_path = db_path
        self.keys = dict(pinned_provider_keys)
        with sqlite3.connect(db_path) as con:
            con.execute("CREATE TABLE IF NOT EXISTS seen(provider TEXT NOT NULL, sequence INTEGER NOT NULL, operation TEXT NOT NULL, PRIMARY KEY(provider,sequence), UNIQUE(provider,operation))")

    def accept(self, envelope):
        if type(envelope) is not dict or set(envelope) != {"event", "signature"}:
            return "INVALID_ENVELOPE"
        e = envelope["event"]
        if not valid_event(e):
            return "INVALID_ENVELOPE"
        key = self.keys.get(e["provider_id"])
        if key is None:
            return "UNTRUSTED_PROVIDER"
        sig = envelope["signature"]
        if type(sig) is not str or len(sig) != 128:
            return "INVALID_SIGNATURE"
        try:
            key.verify(bytes.fromhex(sig), DOMAIN + canonical(e))
        except (InvalidSignature, ValueError, TypeError):
            return "INVALID_SIGNATURE"
        try:
            with sqlite3.connect(self.db_path, timeout=10) as con:
                con.execute("INSERT INTO seen VALUES (?,?,?)",
                    (e["provider_id"], e["sequence"], e["operation_id"]))
        except sqlite3.IntegrityError:
            return "REPLAY_OR_DUPLICATE"
        return "AUTHENTICATED_SYNTHETIC_EVENT"
