#!/usr/bin/env python3
"""Project-authored saved-evidence check of a captured locked HTTP evaluation.

The expected request, complete profile snapshot, and signer fingerprints must
come from the host, not the HTTP response. This does not replay AML policy or
HTML generation and never authorizes rendering.
"""
import json
import pathlib
import re
import sys

from verify_evidence_capsule import canonical, unique_pairs, reject_constant, parse_js_int, verify

MAX_FILE_BYTES = 8 * 1024 * 1024
NONCE = re.compile(r"[0-9a-f]{64}\Z")


def failure(reason):
    return {"protocol": "aml-locked-http-python-report/2", "verified": False,
            "status": "blocked", "render_eligible": False,
            "execution_replayed": False, "profile_snapshot_bound": False,
            "reason": reason}


def read_json(filename):
    path = pathlib.Path(filename)
    if path.stat().st_size > MAX_FILE_BYTES:
        raise ValueError("input_too_large")
    return json.loads(path.read_text(encoding="utf-8"),
                      object_pairs_hook=unique_pairs, parse_constant=reject_constant, parse_int=parse_js_int)


def check_exchange(exchange, capsule, expected, policy):
    if isinstance(expected, dict) and expected.get("protocol") == "aml-locked-http-host-expected/1":
        return failure("host_profile_snapshot_required")
    if (not isinstance(expected, dict) or set(expected) !=
        {"protocol", "intent", "profile", "profile_snapshot", "context", "request_nonce"} or
        expected["protocol"] != "aml-locked-http-host-expected/2" or
        not isinstance(expected["intent"], dict) or
        not isinstance(expected["context"], dict) or
        not isinstance(expected["profile"], str) or not expected["profile"] or
        not isinstance(expected["profile_snapshot"], dict) or
        set(expected["profile_snapshot"]) != {"id", "description", "policies"} or
        expected["profile_snapshot"].get("id") != expected["profile"] or
        not isinstance(expected["profile_snapshot"].get("description"), str) or
        not isinstance(expected["profile_snapshot"].get("policies"), list) or
        not expected["profile_snapshot"]["policies"] or
        any(not isinstance(item, str) or not item for item in expected["profile_snapshot"]["policies"]) or
        not isinstance(expected["request_nonce"], str) or
        not NONCE.fullmatch(expected["request_nonce"])):
        return failure("invalid_host_expectation")
    if (not isinstance(exchange, dict) or set(exchange) != {"protocol", "http_status", "body"} or
        exchange["protocol"] != "aml-locked-http-exchange/1" or
        type(exchange["http_status"]) is not int or exchange["http_status"] != 200 or
        not isinstance(exchange["body"], dict)):
        return failure("invalid_http_exchange")
    body = exchange["body"]
    if (body.get("protocol") != "aml-http-deployment-evaluation/1" or
        body.get("policy_source") != "server" or body.get("mode") != "enforce" or
        body.get("failure_mode") != "closed" or body.get("evaluation_error", object()) is not None):
        return failure("unexpected_deployment_policy")
    receipt = body.get("receipt")
    if not isinstance(receipt, dict) or not isinstance(receipt.get("signature"), dict) or receipt.get("version") != "1.1":
        return failure("unsigned_or_unsupported_receipt")
    if not isinstance(capsule, dict) or not isinstance(capsule.get("receipt"), dict):
        return failure("invalid_capsule")
    if canonical(receipt) != canonical(capsule["receipt"]):
        return failure("capsule_response_mismatch")
    try:
        capsule_report = verify(capsule, policy)
    except (ValueError, KeyError, TypeError, AttributeError, IndexError, OverflowError):
        return failure("invalid_capsule_or_trust")
    if not capsule_report["verified"] or not capsule_report["attribution_bound"]:
        return failure("invalid_capsule_or_trust")
    if (canonical(receipt.get("profile")) != canonical(expected["profile_snapshot"]) or
        receipt.get("request_nonce") != expected["request_nonce"] or
        canonical(receipt.get("intent")) != canonical(expected["intent"]) or
        canonical(receipt.get("context")) != canonical(expected["context"])):
        return failure("receipt_binding_mismatch")
    allowed = receipt["selected_render"]["suppressed"] == 0
    if (body.get("aml_allowed") is not allowed or
        body.get("effective_allowed") is not allowed or
        body.get("would_suppress") is not (not allowed)):
        return failure("decision_mismatch")
    return {"protocol": "aml-locked-http-python-report/2", "verified": True,
            "status": "declared_allow" if allowed else "declared_suppressed", "render_eligible": False,
            "execution_replayed": False, "profile_snapshot_bound": True,
            "reason": "verified_declared_allow" if allowed else "verified_declared_suppression",
            "receipt_sha256": receipt["receipt_sha256"], "output_sha256": receipt["output_sha256"],
            "signer_fingerprint": receipt["signature"]["public_key_sha256"],
            "scope": "Project-authored Python verification of saved signature, evidence, host profile snapshot, and declared outcome. No AML execution replay, render authorization, external witness, live transport, or rendered UI proof."}


if __name__ == "__main__":
    if len(sys.argv) != 5:
        report = failure("usage: verify_http_exchange.py <exchange.json> <capsule.json> <host-expected.json> <trusted-policy.json>")
    else:
        try:
            report = check_exchange(*(read_json(name) for name in sys.argv[1:]))
        except (OSError, ValueError, UnicodeError, TypeError, KeyError, IndexError, RecursionError, OverflowError):
            report = failure("invalid_input")
    print(json.dumps(report, indent=2, ensure_ascii=False))
    sys.exit(0 if report["verified"] else 1)
