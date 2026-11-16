"""SEF/2 experimental Ed25519 receipts with public-key verification.

Signatures attest to key possession and bytes, not actual execution.
Keys are ephemeral in this test fixture; no production custody or PKI.
"""
import hashlib
import json
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

DOMAIN = b"AML-SEF2-ED25519-RECEIPT-V1\x00"

def canonical(v):
    return json.dumps(v, sort_keys=True, separators=(",", ":"),
        ensure_ascii=True, allow_nan=False).encode("utf-8")

def key_id(public_key):
    from cryptography.hazmat.primitives import serialization
    raw = public_key.public_bytes(encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw)
    return hashlib.sha256(raw).hexdigest()

def issue(private_key, role, op, request_sha256, state, evidence_sha256):
    if role not in ("authority", "provider", "witness"):
        raise ValueError("role")
    if any(type(s) is not str for s in (op, request_sha256, state, evidence_sha256)):
        raise ValueError("fields")
    if any(len(d) != 64 or any(c not in "0123456789abcdef" for c in d)
        for d in (request_sha256, evidence_sha256)):
        raise ValueError("digest")
    public = private_key.public_key()
    payload = {"version": 1, "role": role, "key_id": key_id(public),
        "operation_id": op, "request_sha256": request_sha256,
        "state": state, "evidence_sha256": evidence_sha256}
    return {"payload": payload,
        "signature": private_key.sign(DOMAIN + canonical(payload)).hex()}

def verify(envelope, role, trusted_public_keys):
    """trusted_public_keys is an external role -> key_id -> public key trust map."""
    if type(envelope) is not dict or set(envelope) != {"payload", "signature"}:
        return False
    p = envelope["payload"]
    required = {"version", "role", "key_id", "operation_id",
        "request_sha256", "state", "evidence_sha256"}
    if type(p) is not dict or set(p) != required:
        return False
    if type(p["version"]) is not int or p["version"] != 1 or p["role"] != role:
        return False
    if any(type(p[k]) is not str for k in required - {"version"}):
        return False
    if any(len(p[k]) != 64 or any(c not in "0123456789abcdef" for c in p[k])
        for k in ("key_id", "request_sha256", "evidence_sha256")):
        return False
    if type(envelope["signature"]) is not str or len(envelope["signature"]) != 128:
        return False
    try:
        key = trusted_public_keys[role][p["key_id"]]
        if key_id(key) != p["key_id"]:
            return False
        key.verify(bytes.fromhex(envelope["signature"]), DOMAIN + canonical(p))
        return True
    except (KeyError, ValueError, TypeError, InvalidSignature, AttributeError):
        return False

def reconcile(authority, provider, keys):
    if not verify(authority, "authority", keys):
        return "UNTRUSTED_AUTHORITY"
    if not verify(provider, "provider", keys):
        return "UNTRUSTED_PROVIDER"
    a, p = authority["payload"], provider["payload"]
    if (a["operation_id"], a["request_sha256"]) != (p["operation_id"], p["request_sha256"]):
        return "EVIDENCE_CONFLICT"
    if a["state"] != "CONSUMED" or p["state"] != "PROVIDER_REPORTED":
        return "INCOMPLETE"
    return "SIGNED_CLAIMS_ONLY"
