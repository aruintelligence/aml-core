#!/usr/bin/env python3
"""Project-authored independent verifier for ĀML capsule JSON subset.

Signed v1.1 receipts require an external trusted receipt-key fingerprint list.
Embedded public keys alone do not establish a trusted signer or history.
"""
import base64
import binascii
import hashlib
import json
import math
import pathlib
import re
import sys
from decimal import Decimal

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

BOUNDARY = "Project-authored declared inputs. Integrity is not authenticity, independent validation, or proof of human impact."
FIELDS = {"protocol", "canonicalization", "claim_boundary", "summary", "receipt", "digests"}
SIGNATURE_FIELDS = {"protocol", "version", "algorithm", "signer", "signed_at", "public_key_pem", "public_key_sha256", "signature_base64"}
FINGERPRINT = re.compile(r"[a-f0-9]{64}\Z")
UTC = re.compile(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?Z\Z")
MAX_SAFE_INTEGER = 2**53 - 1


def unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def reject_constant(value):
    raise ValueError(f"unsupported JSON constant: {value}")


def parse_js_int(raw):
    # JSON.parse represents every JSON number as binary64. Preserve small positive
    # and negative integers for structural checks, but retain the sign of -0.
    if raw == "-0":
        return -0.0
    number = int(raw)
    if abs(number) <= MAX_SAFE_INTEGER:
        return number
    rounded = float(raw)
    if not math.isfinite(rounded):
        raise ValueError("unsupported non-finite JSON number")
    return rounded


def number_text(value):
    # Match JSON.stringify's fixed/exponent boundary for finite binary64 numbers.
    # repr(float) supplies the shortest round-trip digits; Decimal only places the point.
    if type(value) is int:
        if abs(value) <= MAX_SAFE_INTEGER:
            return str(value)
        try:
            value = float(value)
        except OverflowError as error:
            raise ValueError("unsupported non-finite JSON number") from error
    if not math.isfinite(value):
        raise ValueError("unsupported non-finite JSON number")
    if value == 0:
        return "0"
    sign = "-" if value < 0 else ""
    decimal = Decimal(repr(abs(value))).normalize()
    exponent = decimal.adjusted()
    if -6 <= exponent < 21:
        return sign + format(decimal, "f")
    digits = "".join(str(digit) for digit in decimal.as_tuple().digits)
    coefficient = digits[0] + ("." + digits[1:] if len(digits) > 1 else "")
    return sign + coefficient + "e" + ("+" if exponent >= 0 else "") + str(exponent)


def utf16_key(value):
    return value.encode("utf-16-be", errors="surrogatepass")


def array_index(key):
    # JSON.stringify enumerates these keys numerically, even after Object.fromEntries.
    if (key == "0" or (len(key) <= 10 and key.isascii() and key.isdecimal() and key[0] != "0")):
        number = int(key)
        if number < 2**32 - 1:
            return number
    return None


def string_text(value):
    # Well-formed JSON.stringify escapes lone surrogates; Python's ensure_ascii=False
    # leaves them raw, which cannot be encoded as UTF-8.
    escaped = json.dumps(value, ensure_ascii=False)
    return "".join(f"\\u{ord(char):04x}" if 0xD800 <= ord(char) <= 0xDFFF else char
                   for char in escaped)


def canonical(value, *, receipt_order=False):
    def serialize(item):
        if isinstance(item, dict):
            if any(not isinstance(key, str) for key in item):
                raise ValueError("non-string JSON object key")
            keys = sorted(item, key=utf16_key)
            if not receipt_order:
                indices = [key for key in keys if array_index(key) is not None]
                keys = sorted(indices, key=array_index) + [key for key in keys if array_index(key) is None]
            return "{" + ",".join(serialize(key) + ":" + serialize(item[key]) for key in keys) + "}"
        if isinstance(item, list):
            return "[" + ",".join(serialize(child) for child in item) + "]"
        if type(item) is str:
            return string_text(item)
        if item is None or type(item) is bool:
            return json.dumps(item)
        if type(item) in (int, float):
            return number_text(item)
        raise ValueError("unsupported JSON value")

    return serialize(value).encode("utf-8")


def hash_value(value):
    # The accountable receipt and audit stream use hand-built sorted JSON; unlike
    # the capsule's Object.fromEntries + JSON.stringify, index keys stay lexical.
    return hashlib.sha256(canonical(value, receipt_order=True)).hexdigest()


def hash_text(value):
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def js_integer(value):
    # Number.isInteger(-0) is true; Python's int type check would reject it.
    return type(value) is int or (type(value) is float and math.isfinite(value) and value.is_integer())


def same_number(actual, expected, *, object_is=False):
    # JS uses === for consumed values and Object.is for before/after/remaining.
    # Python's True == 1 and -0.0 == 0.0 must not silently change that contract.
    if actual is None or expected is None:
        return actual is None and expected is None
    if type(actual) not in (int, float) or type(expected) not in (int, float):
        return False
    if object_is and actual == expected == 0:
        return math.copysign(1, actual) == math.copysign(1, expected)
    return actual == expected


def same_json_value(actual, expected):
    if type(actual) is dict and type(expected) is dict:
        return (actual.keys() == expected.keys() and
                all(same_json_value(actual[key], expected[key]) for key in actual))
    if type(actual) is list and type(expected) is list:
        return len(actual) == len(expected) and all(same_json_value(a, b) for a, b in zip(actual, expected))
    if type(actual) in (int, float) or type(expected) in (int, float):
        return same_number(actual, expected, object_is=True)
    return type(actual) is type(expected) and actual == expected


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

    # JavaScript adds and subtracts binary64 Numbers, even when each input is a
    # safe integer. Python integer arithmetic would diverge after the sum crosses
    # 2**53, rejecting an otherwise valid signed receipt.
    remaining, consumed = (None if budget is None else float(budget)), 0.0
    for index, entry in enumerate(ledger["entries"]):
        amount = entry.get("amount_requested")
        if type(amount) not in (int, float) or amount < 0:
            return False
        allowed = budget is None or amount <= remaining
        charged = float(amount) if allowed else 0.0
        after = None if budget is None else max(0.0, remaining - charged)
        if (not js_integer(entry.get("sequence")) or entry.get("sequence") != index or entry.get("allowed") is not allowed or
            not same_number(entry.get("budget_before"), remaining, object_is=True) or
            not same_number(entry.get("amount_consumed"), charged) or
            not same_number(entry.get("budget_after"), after, object_is=True)):
            return False
        consumed += charged
        remaining = after
    return (same_number(ledger.get("consumed"), consumed) and
            same_number(ledger.get("remaining"), remaining, object_is=True))


def valid_audit(stream):
    if stream.get("protocol") != "ĀML Runtime Audit Stream" or not isinstance(stream.get("entries"), list):
        return False
    previous = None
    for index, entry in enumerate(stream["entries"]):
        core = {key: entry[key] for key in ("sequence", "timestamp", "event_type", "payload", "previous_hash")}
        if not js_integer(entry["sequence"]) or entry["sequence"] != index or entry["previous_hash"] != previous or entry["entry_hash"] != hash_value(core):
            return False
        previous = entry["entry_hash"]
    return True


def valid_audit_receipt_binding(receipt):
    stream = receipt["runtime_audit_stream"]
    entries = stream["entries"]
    if (stream.get("version") != "1.0" or stream.get("created_at") != receipt["timestamp"] or
        not isinstance(entries, list) or len(entries) != 5):
        return False
    expected = [
        ("intent_received", {"intent_sha256": receipt["intent_sha256"], "profile_id": receipt["profile"]["id"]}),
        ("aml_generated", {"aml_sha256": receipt["aml_sha256"]}),
        ("policy_simulated", {"simulation_sha256": receipt["simulation_sha256"],
                              "policies": receipt["profile"]["policies"]}),
        ("policy_selected", {"policy_id": receipt["selected_render"]["policy_id"],
                             "decision_sha256": receipt["decision_sha256"],
                             "attention_ledger_remaining": receipt["attention_ledger"]["remaining"],
                             "attention_ledger_consumed": receipt["attention_ledger"]["consumed"]}),
        ("output_rendered", {"output_sha256": receipt["output_sha256"]}),
    ]
    return all(entry.get("timestamp") == receipt["timestamp"] and entry.get("event_type") == event_type and
               same_json_value(entry.get("payload"), payload)
               for entry, (event_type, payload) in zip(entries, expected))


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
        "counts": js_integer(selected["allowed"]) and js_integer(selected["suppressed"])
                  and selected["allowed"] == sum(item["render_allowed"] is True for item in decisions)
                  and selected["suppressed"] == sum(item["render_allowed"] is not True for item in decisions),
        "audit": hash_value(receipt["runtime_audit_stream"]) == receipt["audit_stream_sha256"]
                 and valid_audit(receipt["runtime_audit_stream"]) and receipt["runtime_audit_verified"] is True,
        "audit_binding": valid_audit_receipt_binding(receipt),
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
                             object_pairs_hook=unique_pairs, parse_constant=reject_constant, parse_int=parse_js_int)
        policy = json.loads(pathlib.Path(sys.argv[2]).read_text(encoding="utf-8"),
                            object_pairs_hook=unique_pairs, parse_constant=reject_constant, parse_int=parse_js_int) if len(sys.argv) == 3 else None
        report = verify(capsule, policy)
    except (ValueError, KeyError, TypeError, OSError, OverflowError, RecursionError) as error:
        report = {"protocol": "aml-evidence-capsule-python-report/1", "verified": False, "reason": str(error)}
    print(json.dumps(report, indent=2, ensure_ascii=False))
    sys.exit(0 if report["verified"] else 1)
