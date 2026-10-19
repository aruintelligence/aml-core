#!/usr/bin/env python3
"""Dependency-free, project-authored Python verifier for saved signed quorums.

Implements the published JSON/signature contract without importing AML JavaScript.
Only the cross-language safe JSON domain is accepted for signed bytes: safe
integers, no floats, and BMP object keys. This is not an external certification.
"""

import argparse
import base64
import binascii
import datetime as dt
import hashlib
import json
import re
import sys

from verify_witness import P, parse_time, verify_bundle, verify_p256_raw_signature

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
TRUST_GROUP = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
REPLAYABLE_WITNESS_CHECKS = (
    "bundle_integrity", "receipt_integrity", "evidence_integrity",
    "challenge_freshness", "challenge_binding", "session_signature",
)
REQUIRED_WITNESS_CHECKS = REPLAYABLE_WITNESS_CHECKS + ("verifier_held_challenge",)
INPUT_HASH_FIELDS = (
    "quorum_sha256", "policy_sha256", "witness_bundle_sha256", "held_challenge_sha256",
)
REPORT_TIME = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$")


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
            return False, "AML_SIGNED_REPORT_SIGNATURE_ENCODING_INVALID", None
        signature_bytes = base64.urlsafe_b64decode(signature + "==")
        if (len(signature_bytes) != 64 or
                base64.urlsafe_b64encode(signature_bytes).rstrip(b"=").decode("ascii") != signature):
            return False, "AML_SIGNED_REPORT_SIGNATURE_ENCODING_INVALID", None
        valid, _ = verify_p256_raw_signature(jwk, canonical(report), signature)
        if not valid:
            return False, "AML_SIGNED_REPORT_SIGNATURE_INVALID", None
        return True, "AML_SIGNED_REPORT_VALID", hashlib.sha256(point).hexdigest()
    except (ValueError, TypeError, KeyError, UnicodeError, binascii.Error):
        return False, "AML_PY_SIGNED_REPORT_UNSUPPORTED", None


def validate_policy(policy):
    if not isinstance(policy, dict):
        raise ValueError("AML_SIGNED_QUORUM_POLICY_INVALID")
    veto_dissent = policy.get("schema") == "aml-signed-quorum-held-policy/5"
    complete_claims = veto_dissent or policy.get("schema") == "aml-signed-quorum-held-policy/4"
    material_pinned = complete_claims or policy.get("schema") == "aml-signed-quorum-held-policy/3"
    grouped = material_pinned or policy.get("schema") == "aml-signed-quorum-held-policy/2"
    fields = ({"artifact_hash", "artifact_type", "group_threshold", "prototype", "schema", "threshold", "trusted_keys"}
              if grouped else {"artifact_hash", "artifact_type", "prototype", "schema", "threshold", "trusted_key_fingerprints"})
    if complete_claims:
        fields.add("require_complete_witness_claims")
    if veto_dissent:
        fields.add("reject_trusted_dissent")
    if (set(policy) != fields or
            policy.get("schema") not in ("aml-signed-quorum-held-policy/1", "aml-signed-quorum-held-policy/2",
                                         "aml-signed-quorum-held-policy/3", "aml-signed-quorum-held-policy/4",
                                         "aml-signed-quorum-held-policy/5") or
            policy.get("prototype") is not True or
            (complete_claims and (policy.get("require_complete_witness_claims") is not True or
                                  policy.get("artifact_type") != "aml-witness-bundle/1")) or
            (veto_dissent and policy.get("reject_trusted_dissent") is not True)):
        raise ValueError("AML_SIGNED_QUORUM_POLICY_INVALID")
    check_json(policy)
    if (not isinstance(policy["artifact_type"], str) or
            not policy["artifact_type"].strip() or
            not isinstance(policy["artifact_hash"], str) or
            not HEX64.fullmatch(policy["artifact_hash"])):
        raise ValueError("AML_SIGNED_QUORUM_POLICY_ARTIFACT_INVALID")
    if grouped:
        entries = policy["trusted_keys"]
        if (not isinstance(entries, list) or any(
            not isinstance(entry, dict) or
            set(entry) != ({"verifier_key_fingerprint", "key_material_fingerprint", "trust_group"}
                           if material_pinned else {"verifier_key_fingerprint", "trust_group"}) or
            not isinstance(entry["trust_group"], str) or
            not TRUST_GROUP.fullmatch(entry["trust_group"])
            for entry in entries
        )):
            raise ValueError("AML_SIGNED_QUORUM_POLICY_GROUPS_INVALID")
    keys = ([entry["verifier_key_fingerprint"] for entry in entries]
            if grouped else policy["trusted_key_fingerprints"])
    if (not isinstance(keys, list) or not 1 <= len(keys) <= 64 or
            any(not isinstance(k, str) or not HEX64.fullmatch(k) for k in keys) or
            len(set(keys)) != len(keys)):
        raise ValueError("AML_SIGNED_QUORUM_POLICY_KEYS_INVALID")
    if material_pinned:
        materials = [entry["key_material_fingerprint"] for entry in entries]
        if (any(not isinstance(value, str) or not HEX64.fullmatch(value) for value in materials) or
                len(set(materials)) != len(materials)):
            raise ValueError("AML_SIGNED_QUORUM_POLICY_MATERIAL_INVALID")
    if type(policy["threshold"]) is not int or not 1 <= policy["threshold"] <= len(keys):
        raise ValueError("AML_SIGNED_QUORUM_POLICY_THRESHOLD_INVALID")
    if grouped:
        groups = {entry["trust_group"] for entry in entries}
        if type(policy["group_threshold"]) is not int or not 1 <= policy["group_threshold"] <= len(groups):
            raise ValueError("AML_SIGNED_QUORUM_POLICY_GROUP_THRESHOLD_INVALID")


def validate_input_expectations(expectations, policy=None, with_witness=False):
    if (not isinstance(expectations, dict) or
            expectations.get("schema") != "aml-signed-quorum-input-expectations/1" or
            expectations.get("prototype") is not True or
            expectations.get("canonicalization") != "sorted-json-v1" or
            set(expectations) - {"schema", "prototype", "canonicalization", *INPUT_HASH_FIELDS}):
        raise ValueError("AML_SIGNED_QUORUM_INPUT_EXPECTATIONS_INVALID")
    check_json(expectations)
    pinned = [field for field in INPUT_HASH_FIELDS if field in expectations]
    if (not pinned or any(not isinstance(expectations[field], str) or
                          not HEX64.fullmatch(expectations[field]) for field in pinned)):
        raise ValueError("AML_SIGNED_QUORUM_INPUT_EXPECTATIONS_INVALID")
    if ((policy is None and "policy_sha256" in pinned) or
            (not with_witness and any(field in pinned for field in
                                      ("witness_bundle_sha256", "held_challenge_sha256")))):
        raise ValueError("AML_SIGNED_QUORUM_INPUT_EXPECTATIONS_MISSING_INPUT")
    return pinned


def canonical_report_time(value):
    if not isinstance(value, str) or not REPORT_TIME.fullmatch(value):
        raise ValueError("invalid_report_time")
    parsed = parse_time(value)
    if parsed.isoformat(timespec="milliseconds").replace("+00:00", "Z") != value:
        raise ValueError("invalid_report_time")
    return parsed


def conflicting_witness_claims(report, bundle, replay_now):
    conflicts = []
    fingerprint = bundle["attestation"]["session_key_fingerprint"]
    expiry = bundle["challenge"]["expires_at"]
    for field, expected in (("session_key_fingerprint", fingerprint), ("challenge_expires_at", expiry)):
        if report.get(field) is not None and report[field] != expected:
            conflicts.append(field)
    checked_at = report.get("checked_at")
    if checked_at is not None:
        try:
            checked = canonical_report_time(checked_at)
            earliest = max(
                parse_time(bundle["challenge"]["issued_at"]),
                canonical_report_time(bundle["created_at"]),
                canonical_report_time(bundle["attestation"]["issued_at"]),
            )
            if not earliest <= checked <= parse_time(expiry) or checked > replay_now:
                raise ValueError("invalid_report_time")
        except (ValueError, TypeError, OverflowError):
            conflicts.append("checked_at")
    checks = report.get("checks")
    if not isinstance(checks, dict):
        conflicts.append("checks")
    else:
        for name, value in checks.items():
            if type(value) is not bool or (name in REPLAYABLE_WITNESS_CHECKS and value is not True):
                conflicts.append(f"checks.{name}")
    return conflicts


def unsatisfied_witness_claims(report):
    fields = [name for name in ("session_key_fingerprint", "challenge_expires_at", "checked_at")
              if report.get(name) is None]
    checks = report.get("checks")
    fields.extend(f"checks.{name}" for name in REQUIRED_WITNESS_CHECKS
                  if not isinstance(checks, dict) or checks.get(name) is not True)
    return fields


def verify_quorum(quorum, policy=None, witness_bundle=None, expected_challenge=None,
                  expected_input_fingerprints=None):
    # Direct Python callers need the same held-input validation as the CLI.
    # Otherwise an invalid zero-threshold policy can pass, or a supplied
    # witness bundle can be silently ignored without its retained challenge.
    if policy is not None:
        validate_policy(policy)
    if (witness_bundle is None) != (expected_challenge is None):
        raise ValueError("AML_SIGNED_QUORUM_WITNESS_INPUTS_REQUIRED")
    if expected_challenge is not None and not isinstance(expected_challenge, dict):
        raise ValueError("AML_SIGNED_QUORUM_HELD_CHALLENGE_INVALID")
    if (policy is not None and policy["schema"] in ("aml-signed-quorum-held-policy/4",
                                                    "aml-signed-quorum-held-policy/5") and
            expected_challenge is None):
        raise ValueError("AML_SIGNED_QUORUM_POLICY_WITNESS_REQUIRED")
    with_witness = expected_challenge is not None
    pinned_inputs = (validate_input_expectations(expected_input_fingerprints, policy, with_witness)
                     if expected_input_fingerprints is not None else [])
    checked_conditions = ["valid", "threshold_met"]
    if policy is not None:
        checked_conditions.append("policy_met")
    if with_witness:
        checked_conditions.extend(("witness_met", "replayable_claims_consistent"))
    if expected_input_fingerprints is not None:
        checked_conditions.append("inputs_met")

    def with_requested_conditions(result):
        unmet = [name for name in checked_conditions if result.get(name) is not True]
        result["requested_conditions_met"] = not unmet
        result["requested_conditions"] = {"checked": checked_conditions, "unmet": unmet}
        return result

    rejected = {"valid": False, "threshold_met": False}
    if policy is not None:
        rejected["policy_met"] = False
    if with_witness:
        rejected.update(witness_met=False, replayable_claims_consistent=False)
    if expected_input_fingerprints is not None:
        rejected["inputs_met"] = False
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
        material_pinned = policy is not None and policy["schema"] in (
            "aml-signed-quorum-held-policy/3", "aml-signed-quorum-held-policy/4",
            "aml-signed-quorum-held-policy/5")
        veto_dissent = policy is not None and policy["schema"] == "aml-signed-quorum-held-policy/5"
        grouped = material_pinned or (policy is not None and policy["schema"] == "aml-signed-quorum-held-policy/2")
        assignments = ({entry["verifier_key_fingerprint"]: entry
                        for entry in policy["trusted_keys"]} if grouped else {})
        allowed = (set(assignments) if grouped else
                   set(policy["trusted_key_fingerprints"]) if policy is not None else set())
        material_groups = {}
        conflicting_materials = []
        mismatched_pins = []
        trusted_dissent = []
        pinned_materials = ({entry["key_material_fingerprint"] for entry in policy["trusted_keys"]}
                            if veto_dissent else set())
        artifact_matches = (policy is not None and
                            artifact_type == policy["artifact_type"] and
                            artifact_hash == policy["artifact_hash"])
        for index, (envelope, (ok, reason, key_material)) in enumerate(zip(reports, signed)):
            if not ok:
                if reason not in reasons:
                    reasons.append(reason)
            elif envelope["report"]["valid"]:
                valid_reports += 1
                endorsers.add(key_material)
                if artifact_matches and envelope["verifier_key_fingerprint"] in allowed:
                    if (material_pinned and
                            assignments[envelope["verifier_key_fingerprint"]]["key_material_fingerprint"] != key_material):
                        if envelope["verifier_key_fingerprint"] not in mismatched_pins:
                            mismatched_pins.append(envelope["verifier_key_fingerprint"])
                        continue
                    trusted.add(key_material)
                    if grouped:
                        group = assignments[envelope["verifier_key_fingerprint"]]["trust_group"]
                        if key_material in material_groups and material_groups[key_material] != group:
                            if key_material not in conflicting_materials:
                                conflicting_materials.append(key_material)
                        else:
                            material_groups[key_material] = group
            else:
                if artifact_matches and veto_dissent and key_material in pinned_materials:
                    trusted_dissent.append({"report_index": index,
                                            "key_material_fingerprint": key_material})
                if envelope["report"]["reason"] not in reasons:
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
            distinct_groups = len({group for material, group in material_groups.items()
                                   if material not in conflicting_materials})
            result["policy_met"] = (valid and artifact_matches and len(trusted) >= policy["threshold"] and
                                    (not grouped or (distinct_groups >= policy["group_threshold"] and
                                                     not conflicting_materials)) and
                                    (not material_pinned or not mismatched_pins) and
                                    (not veto_dissent or not trusted_dissent))
            result["policy_evaluation"] = {
                "artifact_matches": artifact_matches, "distinct_trusted_keys": len(trusted),
                "threshold": policy["threshold"],
                **({"distinct_trust_groups": distinct_groups, "group_threshold": policy["group_threshold"],
                    "conflicting_key_material_fingerprints": conflicting_materials} if grouped else {}),
                **({"mismatched_key_fingerprints": mismatched_pins} if material_pinned else {}),
                **({"trusted_dissent": trusted_dissent} if veto_dissent else {}),
            }
        if with_witness:
            # Use a single millisecond snapshot for freshness and its reported
            # observation time. This local clock is not an authenticated clock.
            replay_now = dt.datetime.now(dt.timezone.utc)
            replay_now = replay_now.replace(microsecond=replay_now.microsecond // 1000 * 1000)
            witness_valid, witness_reason = verify_bundle(
                witness_bundle, now=replay_now, expected_challenge=expected_challenge)
            bundle_hash = (witness_bundle.get("integrity", {}).get("value")
                           if isinstance(witness_bundle, dict) and
                           isinstance(witness_bundle.get("integrity"), dict) else None)
            witness_artifact_matches = (artifact_type == "aml-witness-bundle/1" and
                                        artifact_hash == bundle_hash)
            result["witness_met"] = valid and witness_valid and witness_artifact_matches
            result["witness_evaluation"] = {
                "evaluated_at": replay_now.isoformat(timespec="milliseconds").replace("+00:00", "Z"),
                "clock_source": "local_system",
                "local_bundle_valid": witness_valid, "reason": witness_reason,
                "artifact_matches": witness_artifact_matches,
            }
            conflicts = []
            positive_signed_reports = 0
            if result["witness_met"]:
                for index, (envelope, (ok, _, _)) in enumerate(zip(reports, signed)):
                    if not ok or envelope["report"]["valid"] is not True:
                        continue
                    positive_signed_reports += 1
                    fields = conflicting_witness_claims(envelope["report"], witness_bundle, replay_now)
                    if fields:
                        conflicts.append({"report_index": index, "fields": fields})
            result["replayable_claims_consistent"] = result["witness_met"] and not conflicts
            result["replayable_claims_evaluation"] = {
                "checked": result["witness_met"],
                "positive_signed_reports": positive_signed_reports,
                "conflicts": conflicts,
            }
        if (policy is not None and policy["schema"] in ("aml-signed-quorum-held-policy/4",
                                                       "aml-signed-quorum-held-policy/5") and valid):
            unsatisfied = []
            if result["witness_met"]:
                for index, (envelope, (ok, _, key_material)) in enumerate(zip(reports, signed)):
                    if (not ok or envelope["report"]["valid"] is not True or
                            envelope["verifier_key_fingerprint"] not in assignments or
                            key_material != assignments[envelope["verifier_key_fingerprint"]]["key_material_fingerprint"]):
                        continue
                    fields = unsatisfied_witness_claims(envelope["report"])
                    if fields:
                        unsatisfied.append({"report_index": index, "fields": fields})
            result["policy_evaluation"]["complete_claims_checked"] = result["witness_met"]
            result["policy_evaluation"]["unsatisfied_claims"] = unsatisfied
            result["policy_met"] = (result["policy_met"] and result["witness_met"] and
                                    result["replayable_claims_consistent"] and not unsatisfied)
        # Fingerprint all supplied canonical JSON inputs, including held inputs
        # outside the saved quorum. An unsupported live witness value has no
        # portable input binding; preserve the separate verification decision.
        try:
            fingerprints = {"canonicalization": "sorted-json-v1", "quorum_sha256": digest(quorum)}
            if policy is not None:
                fingerprints["policy_sha256"] = digest(policy)
            if with_witness:
                fingerprints["witness_bundle_sha256"] = digest(witness_bundle)
                fingerprints["held_challenge_sha256"] = digest(expected_challenge)
            result["input_fingerprints"] = fingerprints
        except (UnsupportedJSON, UnicodeError, RecursionError):
            pass
        if expected_input_fingerprints is not None:
            observed = result.get("input_fingerprints", {})
            unavailable = [field for field in pinned_inputs if field not in observed]
            mismatched = [field for field in pinned_inputs if field in observed and
                          expected_input_fingerprints[field] != observed[field]]
            result["inputs_met"] = not unavailable and not mismatched
            result["input_evaluation"] = {
                "expectations_sha256": digest(expected_input_fingerprints),
                "checked": pinned_inputs, "mismatched": mismatched, "unavailable": unavailable,
            }
        return with_requested_conditions(result)
    except (ValueError, TypeError, KeyError, UnicodeError, RecursionError) as error:
        return with_requested_conditions({**rejected,
                                          "reason": str(error) or "AML_PY_SIGNED_QUORUM_INVALID"})


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
    parser.add_argument("--bundle", help="Saved witness bundle named by the signed quorum")
    parser.add_argument("--challenge", help="Separately retained verifier challenge; requires --bundle")
    parser.add_argument("--expect-inputs", help="Held canonical SHA-256 pins for supplied inputs")
    args = parser.parse_args()
    try:
        if bool(args.bundle) != bool(args.challenge):
            raise ValueError("AML_SIGNED_QUORUM_WITNESS_INPUTS_REQUIRED")
        quorum = load_json(args.quorum)
        policy = load_json(args.policy) if args.policy else None
        if args.policy:
            validate_policy(policy)
            if policy["schema"] in ("aml-signed-quorum-held-policy/4",
                                     "aml-signed-quorum-held-policy/5") and not args.bundle:
                raise ValueError("AML_SIGNED_QUORUM_POLICY_WITNESS_REQUIRED")
        witness_bundle = load_json(args.bundle) if args.bundle else None
        expected_challenge = load_json(args.challenge) if args.challenge else None
        if args.challenge and not isinstance(expected_challenge, dict):
            raise ValueError("AML_SIGNED_QUORUM_HELD_CHALLENGE_INVALID")
        expected_inputs = load_json(args.expect_inputs) if args.expect_inputs else None
        if args.expect_inputs:
            validate_input_expectations(expected_inputs, policy, bool(args.bundle))
        result = verify_quorum(quorum, policy, witness_bundle, expected_challenge, expected_inputs)
    except (OSError, ValueError) as error:
        print(json.dumps({"valid": False, "reason": str(error)}))
        return 1
    print(json.dumps(result, indent=2))
    return 0 if result["requested_conditions_met"] else 2


if __name__ == "__main__":
    sys.exit(main())
