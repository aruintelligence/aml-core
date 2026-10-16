#!/usr/bin/env python3
"""Dependency-free, project-authored Python verifier for saved signed quorums.

Implements the published JSON/signature contract without importing AML JavaScript.
Only the cross-language safe JSON domain is accepted for signed bytes: safe
integers, no floats, and BMP object keys. This is not an external certification.
"""

import argparse
import base64
import binascii
import hashlib
import json
import re
import sys

from verify_witness import P, verify_p256_raw_signature

BOUNDARY = (
    "Threshold agreement means enough supplied reports were validly signed by distinct "
    "public-key fingerprints over the same exact artifact and reported valid. Correctly "
    "signed invalid reports are authenticated dissent and never count toward the "
    "endorsement quorum. Distinct keys do not prove distinct people, organizations, "
    "independence, authorization, certification, or correctness."
)
HEX64 = re.compile(r"^[a-f0-9]{64}$")
BASE64URL = re.compile(r"^[A-Za-z0-9_-]{43}$")
SIGNATURE_B64URL = re.compile(r"^[A-Za-z0-9_-]{86}$")


class UnsupportedJSON(ValueError):
    pass


def check_json(value):
    if value is None or type(value) in (str, bool):
        return
    if type(value) is int and -(2 ** 53 - 1) <= value <= 2 ** 53 - 1:
        return
    if type(value) is list:
        for item in value:
            check_json(item)
        return
    if type(value) is dict:
        for key, item in value.items():
            if not isinstance(key, str) or any(ord(c) > 0xFFFF or 0xD800 <= ord(c) <= 0xDFFF for c in key):
                raise UnsupportedJSON("unsupported_object_key")
            check_json(item)
        return
    raise UnsupportedJSON("unsupported_canonical_value")


def canonical(value):
    check_json(value)
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def public_point(jwk):
    if not isinstance(jwk, dict) or jwk.get("kty") != "EC" or jwk.get("crv") != "P-256":
        raise ValueError("invalid_public_key")
    operations = jwk.get("key_ops")
    if "d" in jwk or (operations is not None and (
        not isinstance(operations, list) or
        any(not isinstance(operation, str) for operation in operations) or
        len(set(operations)) != len(operations) or "verify" not in operations
    )):
        raise ValueError("invalid_key_usage")
    if "ext" in jwk and type(jwk["ext"]) is not bool:
        raise ValueError("invalid_key_usage")
    if jwk.get("use", "sig") != "sig" or jwk.get("alg", "ES256") != "ES256":
        raise ValueError("invalid_key_usage")
    point = []
    for coordinate in ("x", "y"):
        value = jwk.get(coordinate)
        if not isinstance(value, str) or not BASE64URL.fullmatch(value):
            raise ValueError("invalid_public_key")
        raw = base64.urlsafe_b64decode(value + "=")
        if len(raw) != 32 or base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii") != value:
            raise ValueError("invalid_public_key")
        point.append(raw)
    if any(int.from_bytes(raw, "big") >= P for raw in point):
        raise ValueError("invalid_public_key")
    return b"\x04" + point[0] + point[1]


def verify_report(envelope):
    if not isinstance(envelope, dict) or envelope.get("schema") != "aml-signed-verification-report/1":
        return False, "AML_SIGNED_REPORT_INVALID", None
    if envelope.get("algorithm") != "ECDSA-P256-SHA256":
        return False, "AML_SIGNED_REPORT_ALGORITHM_UNSUPPORTED", None
    report = envelope.get("report")
    if not isinstance(report, dict) or report.get("schema") != "aml-verification-report/1":
        return False, "AML_SIGNED_REPORT_REPORT_INVALID", None
    jwk = envelope.get("verifier_public_key_jwk")
    try:
        point = public_point(jwk)
        if digest(jwk) != envelope.get("verifier_key_fingerprint"):
            return False, "AML_SIGNED_REPORT_KEY_FINGERPRINT_MISMATCH", None
        signature = envelope.get("signature")
        if not isinstance(signature, str) or not SIGNATURE_B64URL.fullmatch(signature):
            raise ValueError("invalid_signature")
        signature_bytes = base64.urlsafe_b64decode(signature + "==")
        if base64.urlsafe_b64encode(signature_bytes).rstrip(b"=").decode("ascii") != signature:
            raise ValueError("invalid_signature")
        valid, _ = verify_p256_raw_signature(jwk, canonical(report), signature)
        if not valid:
            return False, "AML_SIGNED_REPORT_SIGNATURE_INVALID", None
        return True, "AML_SIGNED_REPORT_VALID", hashlib.sha256(point).hexdigest()
    except (ValueError, TypeError, KeyError, UnicodeError, binascii.Error):
        return False, "AML_PY_SIGNED_REPORT_UNSUPPORTED", None


def validate_policy(policy):
    fields = {"artifact_hash", "artifact_type", "prototype", "schema", "threshold", "trusted_key_fingerprints"}
    if (not isinstance(policy, dict) or set(policy) != fields or
            policy.get("schema") != "aml-signed-quorum-held-policy/1" or
            policy.get("prototype") is not True):
        raise ValueError("AML_SIGNED_QUORUM_POLICY_INVALID")
    check_json(policy)
    if (not isinstance(policy["artifact_type"], str) or
            not policy["artifact_type"].strip() or
            not isinstance(policy["artifact_hash"], str) or
            not HEX64.fullmatch(policy["artifact_hash"])):
        raise ValueError("AML_SIGNED_QUORUM_POLICY_ARTIFACT_INVALID")
    keys = policy["trusted_key_fingerprints"]
    if (not isinstance(keys, list) or not 1 <= len(keys) <= 64 or
            any(not isinstance(k, str) or not HEX64.fullmatch(k) for k in keys) or
            len(set(keys)) != len(keys)):
        raise ValueError("AML_SIGNED_QUORUM_POLICY_KEYS_INVALID")
    if type(policy["threshold"]) is not int or not 1 <= policy["threshold"] <= len(keys):
        raise ValueError("AML_SIGNED_QUORUM_POLICY_THRESHOLD_INVALID")


def verify_quorum(quorum, policy=None):
    rejected = {"valid": False, "threshold_met": False}
    if policy is not None:
        rejected["policy_met"] = False
    try:
        canonical(quorum)
        if not isinstance(quorum, dict) or quorum.get("schema") != "aml-signed-verification-quorum/1":
            raise ValueError("AML_SIGNED_QUORUM_INVALID")
        reports = quorum.get("signed_reports")
        threshold = quorum.get("threshold")
        if (not isinstance(reports, list) or not 1 <= len(reports) <= 64 or
                type(threshold) is not int or threshold < 1):
            raise ValueError("AML_SIGNED_QUORUM_REPORTS_OR_THRESHOLD_INVALID")
        signed = [verify_report(envelope) for envelope in reports]
        authenticated = [envelope["report"] for envelope, (ok, _, _) in zip(reports, signed) if ok]
        if not authenticated:
            raise ValueError("AML_SIGNED_QUORUM_NO_VALID_SIGNED_REPORTS")
        for report in authenticated:
            if (report.get("prototype") is not True or
                    not isinstance(report.get("verifier"), str) or not report["verifier"].strip() or
                    not isinstance(report.get("artifact_type"), str) or not report["artifact_type"].strip() or
                    not isinstance(report.get("artifact_hash"), str) or not report["artifact_hash"].strip() or
                    type(report.get("valid")) is not bool or
                    not isinstance(report.get("reason"), str) or not report["reason"].strip()):
                raise ValueError("AML_SIGNED_QUORUM_REPORT_INVALID")
        artifact_type = authenticated[0]["artifact_type"]
        artifact_hash = authenticated[0]["artifact_hash"]
        if any(report["artifact_type"] != artifact_type or report["artifact_hash"] != artifact_hash for report in authenticated):
            raise ValueError("AML_SIGNED_QUORUM_ARTIFACT_MISMATCH")

        endorsers = set()
        trusted = set()
        valid_reports = 0
        reasons = []
        allowed = set(policy["trusted_key_fingerprints"]) if policy is not None else set()
        artifact_matches = (policy is not None and
                            artifact_type == policy["artifact_type"] and
                            artifact_hash == policy["artifact_hash"])
        for envelope, (ok, reason, key_material) in zip(reports, signed):
            if not ok:
                if reason not in reasons:
                    reasons.append(reason)
            elif envelope["report"]["valid"]:
                valid_reports += 1
                endorsers.add(key_material)
                if artifact_matches and envelope["verifier_key_fingerprint"] in allowed:
                    trusted.add(key_material)
            elif envelope["report"]["reason"] not in reasons:
                reasons.append(envelope["report"]["reason"])
        invalid_reports = len(reports) - valid_reports
        summary = {
            "distinct_keys": len(endorsers),
            "valid_signatures": len(authenticated),
            "valid_reports": valid_reports,
            "invalid_reports": invalid_reports,
            "threshold_met": valid_reports >= threshold and len(endorsers) >= threshold,
            "unanimous": invalid_reports == 0 and valid_reports == len(reports),
            "disagreement_reasons": reasons,
        }
        rebuilt = {
            "schema": "aml-signed-verification-quorum/1", "prototype": True,
            "artifact_type": artifact_type, "artifact_hash": artifact_hash,
            "threshold": threshold, "signed_reports": reports, "summary": summary,
            "claim_boundary": BOUNDARY,
        }
        valid = canonical(quorum) == canonical(rebuilt)
        result = {"valid": valid, "threshold_met": valid and summary["threshold_met"],
                  "reason": "AML_PY_SIGNED_QUORUM_VALID" if valid else "AML_PY_SIGNED_QUORUM_MISMATCH",
                  "summary": summary}
        if policy is not None:
            result["policy_met"] = valid and artifact_matches and len(trusted) >= policy["threshold"]
            result["policy_evaluation"] = {
                "artifact_matches": artifact_matches, "distinct_trusted_keys": len(trusted),
                "threshold": policy["threshold"],
            }
        return result
    except (ValueError, TypeError, KeyError, UnicodeError, RecursionError) as error:
        return {**rejected, "reason": str(error) or "AML_PY_SIGNED_QUORUM_INVALID"}


def load_json(filename):
    def unique_pairs(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate_json_key")
            result[key] = value
        return result

    with open(filename, encoding="utf-8") as source:
        return json.load(source, object_pairs_hook=unique_pairs,
                         parse_constant=lambda _: (_ for _ in ()).throw(ValueError("non_json_number")))


def main():
    parser = argparse.ArgumentParser(description="Verify a saved AML signed quorum using Python")
    parser.add_argument("quorum")
    parser.add_argument("--policy", help="Separately retained artifact and verifier key expectations")
    args = parser.parse_args()
    try:
        quorum = load_json(args.quorum)
        policy = load_json(args.policy) if args.policy else None
        if policy is not None:
            validate_policy(policy)
    except (OSError, ValueError) as error:
        print(json.dumps({"valid": False, "reason": str(error)}))
        return 1
    result = verify_quorum(quorum, policy)
    print(json.dumps(result, indent=2))
    return 0 if result["valid"] and result["threshold_met"] and result.get("policy_met", True) else 2


if __name__ == "__main__":
    sys.exit(main())
