"""SEF/2 laboratory dual-role receipt envelopes.

HMAC is shared-secret authentication, NOT third-party verifiable signatures.
This is a local test fixture, not a real external witness.
"""
import hashlib
import hmac
import json

ROLES = ("authority", "provider")
DOMAIN = b"AML-SEF2-RECEIPT-V1\x00"

def encode(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
        ensure_ascii=True, allow_nan=False).encode("utf-8")

def issue(role, key, operation_id, request_digest, state, evidence_digest):
    if role not in ROLES or type(key) is not bytes or len(key) < 32:
        raise ValueError("invalid role or key")
    if type(operation_id) is not str or type(request_digest) is not str:
        raise ValueError("invalid identifiers")
    if len(request_digest) != 64 or any(c not in "0123456789abcdef" for c in request_digest):
        raise ValueError("invalid digest")
    payload = {"version": 1, "role": role, "operation_id": operation_id,
        "request_sha256": request_digest, "state": state,
        "evidence_sha256": evidence_digest}
    mac = hmac.new(key, DOMAIN + encode(payload), hashlib.sha256).hexdigest()
    return {"payload": payload, "mac": mac}

def verify(envelope, role, key):
    if role not in ROLES or type(key) is not bytes or len(key) < 32:
        return False
    if type(envelope) is not dict or set(envelope) != {"payload", "mac"}:
        return False
    p = envelope["payload"]
    if type(p) is not dict or set(p) != {"version", "role", "operation_id",
        "request_sha256", "state", "evidence_sha256"}:
        return False
    if p["version"] != 1 or type(p["version"]) is not int or p["role"] != role:
        return False
    if any(type(p[k]) is not str for k in ("operation_id", "request_sha256", "state", "evidence_sha256")):
        return False
    if any(len(p[k]) != 64 or any(c not in "0123456789abcdef" for c in p[k])
        for k in ("request_sha256", "evidence_sha256")):
        return False
    if type(envelope["mac"]) is not str or len(envelope["mac"]) != 64:
        return False
    try:
        expected = hmac.new(key, DOMAIN + encode(p), hashlib.sha256).hexdigest()
    except (TypeError, ValueError, OverflowError):
        return False
    return hmac.compare_digest(envelope["mac"], expected)

def reconcile(authority, provider, authority_key, provider_key):
    """Only corroborate consistent *claims*, never independently assert real execution."""
    if not verify(authority, "authority", authority_key):
        return "UNTRUSTED_AUTHORITY_RECEIPT"
    if not verify(provider, "provider", provider_key):
        return "UNTRUSTED_PROVIDER_RECEIPT"
    a, p = authority["payload"], provider["payload"]
    if a["operation_id"] != p["operation_id"] or a["request_sha256"] != p["request_sha256"]:
        return "EVIDENCE_CONFLICT"
    if a["state"] != "CONSUMED" or p["state"] != "PROVIDER_REPORTED":
        return "INCOMPLETE"
    return "CORROBORATED_CLAIMS_ONLY"
