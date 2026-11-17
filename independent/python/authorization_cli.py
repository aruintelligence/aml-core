#!/usr/bin/env python3
"""Directive 010 exit contract for the Python evidence verifiers.

`verified` is a precondition, never permission. A verifier exits 0 only when
the complete authorization decision is true: the evidence verified AND the
SHA-256 of the canonical trusted-policy file equals the relying party's pin
(`--expected-policy-sha256`, 64 lowercase hex, obtained out of band).
Verified-but-unpinned exits 3. `--diagnostic-only` exits 0 for a verified
result but reports authorized:false and NOT AN AUTHORIZATION DECISION.

Trust-config mode (`--trust-config`, `--trust-state`, `--single-use-store`,
see docs/TRUST_CONFIG.md) mirrors bin/aml.js: it is active when a config is
given or any trust state directory is enrolled (always including
/etc/aml/trust). The config must be trusted; when it sets policy_sha256 the
policy digest must equal it (ANDed with any --expected-policy-sha256); and a
config requiring single use consumes the verifier report once, last.

    python3 independent/python/authorization_cli.py policy-sha256 <policy.json>
"""
import hashlib
import json
import pathlib
import re
import sys

from verify_evidence_capsule import canonical
import trust_config

EXIT_AUTHORIZED = 0
EXIT_NOT_AUTHORIZED = 3
NOT_AN_AUTHORIZATION_DECISION = "NOT AN AUTHORIZATION DECISION"
PIN = re.compile(r"[0-9a-f]{64}\Z")
DIAGNOSTIC_FLAG = "--diagnostic-only"
POLICY_PIN_FLAG = "--expected-policy-sha256"


TRUST_OPTIONS = {}


def split_flags(argv):
    """Remove the Directive 010 flags; return (positional, pin, diagnostic).

    Trust-config flags are removed too and kept in TRUST_OPTIONS for decide()."""
    argv, options = trust_config.take_trust_flags(argv)
    TRUST_OPTIONS.clear()
    TRUST_OPTIONS.update(options)
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


def decide(report, policy, pin, diagnostic, consume=True, single_use_result=None):
    """Attach the decision to `report` and return (report, exit_code).

    `single_use_result` carries a prior decide()'s consumption outcome for the
    same action (a pre-check that already consumed); nothing is consumed twice."""
    trust = trust_config.load_trust(TRUST_OPTIONS)
    artifact = None
    try:
        artifact = trust_config.artifact_sha256({"verifier": pathlib.Path(sys.argv[0]).name, "report": report})
    except (ValueError, TypeError, RecursionError):
        artifact = None
    verified = report.get("verified") is True
    actual = None
    if policy is not None:
        try:
            actual = policy_sha256(policy)
        except (ValueError, TypeError, RecursionError):
            actual = None
    flag_pinned = isinstance(pin, str) and PIN.match(pin) is not None and actual == pin
    config_pin = (trust["decision"].get("effective", {}).get("policy_sha256")
                  if trust is not None and trust_config.config_trusted(trust) else None)
    if config_pin is None:
        policy_pinned = flag_pinned
    else:
        # As in bin/aml.js: a config policy pin is ANDed with any flag pin, never ORed.
        policy_pinned = ((pin is None or flag_pinned)
                         and trust_config.pin_matches(trust["decision"], "policy_sha256", actual))
    conditions = {"evidence_verified": verified, "policy_pinned": policy_pinned is True}
    if trust is not None:
        conditions["trust_config_trusted"] = trust_config.config_trusted(trust)
    if single_use_result is not None:
        once = ("single_use_consumed", single_use_result is True)
    elif consume and not diagnostic:
        once = trust_config.single_use(trust, TRUST_OPTIONS, conditions, "py:" + pathlib.Path(sys.argv[0]).name, artifact)
    else:
        once = ("single_use_consumed", False) if (TRUST_OPTIONS.get("--single-use-store") or (
            trust is not None and trust_config.config_trusted(trust)
            and trust_config.requires_single_use(trust["decision"]))) else None
    if once is not None:
        conditions[once[0]] = once[1] is True
    reasons = []
    if not conditions["evidence_verified"]:
        reasons.append("AML_AUTHZ_EVIDENCE_NOT_VERIFIED")
    if not conditions["policy_pinned"]:
        reasons.append("AML_AUTHZ_POLICY_NOT_PINNED")
    for name in conditions:
        if name in trust_config.TRUST_DENIALS and conditions[name] is not True:
            reasons.append(trust_config.TRUST_DENIALS[name])
    authorized = not reasons and not diagnostic and all(v is True for v in conditions.values())
    if diagnostic:
        reasons = ["AML_AUTHZ_DIAGNOSTIC_ONLY"] + reasons
    report = dict(report, policy_sha256=actual, authorized=authorized, authorization={
        "schema": "aml-authorization-decision/1", "authorized": authorized,
        "decision": "allow" if authorized else "deny",
        "reasons": ["AML_AUTHZ_ALLOW"] if authorized else reasons,
        "required": list(conditions)})
    if trust is not None:
        report["trust"] = trust_config.trust_summary(trust)
    if once is not None:
        report["single_use"] = {"consumed": conditions[once[0]] is True, "artifact_sha256": artifact}
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
