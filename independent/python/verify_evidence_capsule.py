#!/usr/bin/env python3
"""Project-authored independent verifier for ĀML capsule JSON subset.

Signed v1.1 receipts require an external trusted receipt-key fingerprint list.
Embedded public keys alone do not establish a trusted signer or history.
"""
import base64
import binascii
import hashlib
import json
import pathlib
import re
import sys

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

BOUNDARY = "Project-authored declared inputs. Integrity is not authenticity, independent validation, or proof of human impact."
FIELDS = {"protocol", "canonicalization", "claim_boundary", "summary", "receipt", "digests"}
SIGNATURE_FIELDS = {"protocol", "version", "algorithm", "signer", "signed_at", "public_key_pem", "public_key_sha256", "signature_base64"}
FINGERPRINT = re.compile(r"[a-f0-9]{64}\Z")
UTC = re.compile(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?Z\Z")


def unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def reject_constant(value):
    raise ValueError(f"unsupported JSON constant: {value}")


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")


def hash_value(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def hash_text(value):
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def verify_signature(receipt, policy):
    if not isinstance(policy, dict):
        raise ValueError("external_receipt_trust_required")
    trusted = policy.get("trusted_receipt_fingerprints")
    revoked = policy.get("revoked_receipt_fingerprints", [])
    if trusted is None:
        raise ValueError("external_receipt_trust_required")
    if (not isinstance(trusted, list) or not trusted or
        not isinstance(revoked, list) or
        any(not isinstance(item, str) or not FINGERPRINT.fullmatch(item) for item in trusted + revoked)):
        raise ValueError("invalid_receipt_trust_policy")
    signature = receipt["signature"]
    if (not isinstance(signature, dict) or set(signature) != SIGNATURE_FIELDS or
        signature.get("protocol") != "ĀML Execution Receipt Attestation" or signature.get("version") != "1.1" or
        signature.get("algorithm") != "Ed25519" or
        (signature.get("signer") is not None and not isinstance(signature["signer"], str)) or
        not isinstance(signature.get("signed_at"), str) or not UTC.fullmatch(signature["signed_at"])):
        return False
    try:
        key = serialization.load_pem_public_key(signature["public_key_pem"].encode("utf-8"))
        if not isinstance(key, Ed25519PublicKey):
            return False
        der = key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        fingerprint = hashlib.sha256(der).hexdigest()
        if (signature["public_key_sha256"] != fingerprint or fingerprint not in trusted or
            fingerprint in revoked):
            return False
        encoded = signature["signature_base64"]
        raw = base64.b64decode(encoded, validate=True)
        if len(raw) != 64 or base64.b64encode(raw).decode("ascii") != encoded:
            return False
        material = {"protocol": "ĀML Execution Receipt Attestation", "version": "1.1", "algorithm": "Ed25519",
                    "receipt_sha256": receipt["receipt_sha256"], "signer": signature["signer"],
                    "signed_at": signature["signed_at"]}
        key.verify(raw, canonical(material))
        return True
    except (ValueError, TypeError, KeyError, AttributeError, InvalidSignature, binascii.Error):
        return False


def valid_ledger(ledger):
    if ledger.get("protocol") != "ĀML Attention Ledger" or not isinstance(ledger.get("entries"), list):
        return False
    budget = ledger.get("initial_budget")
    if budget is not None and (type(budget) not in (int, float) or budget < 0):
        return False
    remaining, consumed = budget, 0
    for index, entry in enumerate(ledger["entries"]):
        amount = entry.get("amount_requested")
        if type(amount) not in (int, float) or amount < 0:
            return False
        allowed = budget is None or amount <= remaining
        charged = amount if allowed else 0
        after = None if budget is None else max(0, remaining - charged)
        if (type(entry.get("sequence")) is not int or entry.get("sequence") != index or entry.get("allowed") is not allowed or
            entry.get("budget_before") != remaining or entry.get("amount_consumed") != charged or
            entry.get("budget_after") != after):
            return False
        consumed += charged
        remaining = after
    return ledger.get("consumed") == consumed and ledger.get("remaining") == remaining


def valid_audit(stream):
    if stream.get("protocol") != "ĀML Runtime Audit Stream" or not isinstance(stream.get("entries"), list):
        return False
    previous = None
    for index, entry in enumerate(stream["entries"]):
        core = {key: entry[key] for key in ("sequence", "timestamp", "event_type", "payload", "previous_hash")}
        if type(entry["sequence"]) is not int or entry["sequence"] != index or entry["previous_hash"] != previous or entry["entry_hash"] != hash_value(core):
            return False
        previous = entry["entry_hash"]
    return True


def verify(capsule, policy=None):
    if set(capsule) != FIELDS or capsule["protocol"] != "aml-evidence-capsule/1" or capsule["canonicalization"] != "aml-sorted-json/1":
        raise ValueError("unsupported capsule contract")
    if capsule["claim_boundary"] != BOUNDARY or set(capsule["digests"]) != {"sha256", "sha512"}:
        raise ValueError("invalid capsule metadata")
    payload = {key: value for key, value in capsule.items() if key != "digests"}
    data = canonical(payload)
    if capsule["digests"] != {"sha256": hashlib.sha256(data).hexdigest(), "sha512": hashlib.sha512(data).hexdigest()}:
        raise ValueError("capsule digest mismatch or unsupported numeric serialization")

    receipt = capsule["receipt"]
    if receipt.get("protocol") != "ĀML Accountable Execution Receipt":
        raise ValueError("unsupported receipt")
    signed = "signature" in receipt
    if signed and policy is None:
        raise ValueError("external_receipt_trust_required")
    receipt_payload = {key: value for key, value in receipt.items() if key not in ("receipt_sha256", "signature")}
    decisions = receipt["selected_render"]["decisions"]
    selected = receipt["selected_render"]
    checks = {
        "receipt_hash": hash_value(receipt_payload) == receipt["receipt_sha256"],
        "intent": hash_value(receipt["intent"]) == receipt["intent_sha256"],
        "aml": hash_text(receipt["aml_source"]) == receipt["aml_sha256"],
        "simulation": hash_value(receipt["simulations"]) == receipt["simulation_sha256"],
        "decision": hash_value(decisions) == receipt["decision_sha256"],
        "output": hash_text(selected["html"]) == receipt["output_sha256"],
        "counts": type(selected["allowed"]) is int and type(selected["suppressed"]) is int
                  and selected["allowed"] == sum(item["render_allowed"] is True for item in decisions)
                  and selected["suppressed"] == sum(item["render_allowed"] is not True for item in decisions),
        "audit": hash_value(receipt["runtime_audit_stream"]) == receipt["audit_stream_sha256"]
                 and valid_audit(receipt["runtime_audit_stream"]) and receipt["runtime_audit_verified"] is True,
        "ledger": hash_value(receipt["attention_ledger"]) == receipt["attention_ledger_sha256"]
                  and valid_ledger(receipt["attention_ledger"]),
        "signature": not signed or verify_signature(receipt, policy),
    }
    summary = {"timestamp": receipt["timestamp"], "profile_id": receipt["profile"]["id"],
               "allowed": selected["allowed"], "suppressed": selected["suppressed"],
               "receipt_sha256": receipt["receipt_sha256"], "signed": signed}
    checks["summary"] = canonical(capsule["summary"]) == canonical(summary)
    return {"protocol": "aml-evidence-capsule-python-report/1", "verified": all(checks.values()),
            "checks": checks, "attribution_bound": signed and all(checks.values()),
            "scope": "Project-authored Python check of capsules on the canonical JSON subset; signed v1.1 receipts require external trusted fingerprints, not independent witnessing."}


if __name__ == "__main__":
    try:
        if len(sys.argv) not in (2, 3):
            raise ValueError("Usage: python3 independent/python/verify_evidence_capsule.py <capsule.json> [trusted-policy.json]")
        capsule = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"),
                             object_pairs_hook=unique_pairs, parse_constant=reject_constant)
        policy = json.loads(pathlib.Path(sys.argv[2]).read_text(encoding="utf-8"),
                            object_pairs_hook=unique_pairs, parse_constant=reject_constant) if len(sys.argv) == 3 else None
        report = verify(capsule, policy)
    except (ValueError, KeyError, TypeError, OSError, OverflowError, RecursionError) as error:
        report = {"protocol": "aml-evidence-capsule-python-report/1", "verified": False, "reason": str(error)}
    print(json.dumps(report, indent=2, ensure_ascii=False))
    sys.exit(0 if report["verified"] else 1)
