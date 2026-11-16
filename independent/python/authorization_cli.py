#!/usr/bin/env python3
"""Directive 010 exit contract for the Python evidence verifiers.

`verified` is a precondition, never permission. A verifier exits 0 only when
the complete authorization decision is true: the evidence verified AND the
SHA-256 of the canonical trusted-policy file equals the relying party's pin
(`--expected-policy-sha256`, 64 lowercase hex, obtained out of band).
Verified-but-unpinned exits 3. `--diagnostic-only` exits 0 for a verified
result but reports authorized:false and NOT AN AUTHORIZATION DECISION.

    python3 independent/python/authorization_cli.py policy-sha256 <policy.json>
"""
import hashlib
import json
import pathlib
import re
import sys

from verify_evidence_capsule import canonical

EXIT_AUTHORIZED = 0
EXIT_NOT_AUTHORIZED = 3
NOT_AN_AUTHORIZATION_DECISION = "NOT AN AUTHORIZATION DECISION"
PIN = re.compile(r"[0-9a-f]{64}\Z")
DIAGNOSTIC_FLAG = "--diagnostic-only"
POLICY_PIN_FLAG = "--expected-policy-sha256"


def split_flags(argv):
    """Remove the Directive 010 flags; return (positional, pin, diagnostic)."""
    rest, pin, diagnostic, index = [], None, False, 0
    while index < len(argv):
        arg = argv[index]
        if arg == DIAGNOSTIC_FLAG:
            diagnostic = True
        elif arg == POLICY_PIN_FLAG:
            if pin is not None or index + 1 >= len(argv) or argv[index + 1].startswith("--"):
                raise ValueError(f"{POLICY_PIN_FLAG} requires exactly one value")
            pin = argv[index + 1]
            index += 1
        else:
            rest.append(arg)
        index += 1
    return rest, pin, diagnostic


def policy_sha256(policy):
    data = canonical(policy)
    return hashlib.sha256(data if isinstance(data, bytes) else data.encode("utf-8")).hexdigest()


def decide(report, policy, pin, diagnostic):
    """Attach the decision to `report` and return (report, exit_code)."""
    verified = report.get("verified") is True
    actual = None
    if policy is not None:
        try:
            actual = policy_sha256(policy)
        except (ValueError, TypeError, RecursionError):
            actual = None
    conditions = {
        "evidence_verified": verified,
        "policy_pinned": isinstance(pin, str) and PIN.match(pin) is not None and actual == pin,
    }
    reasons = []
    if not conditions["evidence_verified"]:
        reasons.append("AML_AUTHZ_EVIDENCE_NOT_VERIFIED")
    if not conditions["policy_pinned"]:
        reasons.append("AML_AUTHZ_POLICY_NOT_PINNED")
    authorized = not reasons and not diagnostic
    if diagnostic:
        reasons = ["AML_AUTHZ_DIAGNOSTIC_ONLY"] + reasons
    report = dict(report, policy_sha256=actual, authorized=authorized, authorization={
        "schema": "aml-authorization-decision/1", "authorized": authorized,
        "decision": "allow" if authorized else "deny",
        "reasons": ["AML_AUTHZ_ALLOW"] if authorized else reasons,
        "required": ["evidence_verified", "policy_pinned"]})
    if not authorized:
        report["decision_use"] = NOT_AN_AUTHORIZATION_DECISION
    if diagnostic:
        report["diagnostic_only"] = True
        return report, (0 if verified else 1)
    if authorized:
        return report, EXIT_AUTHORIZED
    return report, (EXIT_NOT_AUTHORIZED if verified else 1)


if __name__ == "__main__":
    if len(sys.argv) != 3 or sys.argv[1] != "policy-sha256":
        print(__doc__.strip().splitlines()[-1].strip(), file=sys.stderr)
        sys.exit(2)
    from verify_evidence_archive import strict_json
    print(policy_sha256(strict_json(pathlib.Path(sys.argv[2]).read_text(encoding="utf-8"))))
