"""Three-party evidence consistency gate for synthetic SEF/2 operations.

Witness evidence must be signed by a separately trusted key. This fixture
cannot prove independent observation, key custody, or real-world execution.
"""
from signed_receipt import verify

def adjudicate(authority, provider, witness, trusted_keys):
    if not verify(authority, "authority", trusted_keys):
        return "UNTRUSTED_AUTHORITY"
    if not verify(provider, "provider", trusted_keys):
        return "UNTRUSTED_PROVIDER"
    if witness is None:
        return "MISSING_INDEPENDENT_EVIDENCE"
    if not verify(witness, "witness", trusted_keys):
        return "UNTRUSTED_WITNESS"
    a, p, w = (receipt["payload"] for receipt in (authority, provider, witness))
    if len({a["operation_id"], p["operation_id"], w["operation_id"]}) != 1:
        return "EVIDENCE_CONFLICT"
    if len({a["request_sha256"], p["request_sha256"], w["request_sha256"]}) != 1:
        return "EVIDENCE_CONFLICT"
    if p["evidence_sha256"] != w["evidence_sha256"]:
        return "EVIDENCE_CONFLICT"
    if a["state"] != "CONSUMED" or p["state"] != "PROVIDER_REPORTED":
        return "INCOMPLETE"
    if w["state"] != "OBSERVED_SYNTHETIC_EFFECT":
        return "INCOMPLETE"
    return "THREE_SIGNED_CONSISTENT_CLAIMS"
