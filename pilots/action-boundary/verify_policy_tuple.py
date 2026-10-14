#!/usr/bin/env python3
"""Independent finite expectation for the three policy-rule bindings."""
import hashlib
import itertools
import json
import pathlib
import sys

AXES = {"tool": ["exact", "other"], "effect": ["exact", "other"],
        "resource": ["exact", "other"]}
PROPOSAL = {"protocol": "aml-proposed-action/1", "tool": "send_message", "effect": "send",
            "resource": "team@example.test", "purpose": "Local policy tuple fixture",
            "arguments": {"to": "team@example.test", "body": "Tuple fixture only."}}
PROPOSAL_BINDINGS = {key: PROPOSAL[key] for key in AXES}
OTHER = {"tool": "archive_message", "effect": "write", "resource": "outside@example.test"}
DIGEST = hashlib.sha256(json.dumps(PROPOSAL, sort_keys=True, separators=(",", ":"),
                                   ensure_ascii=False).encode("utf-8")).hexdigest()
PROVENANCE = "project-authored local eight-case rule-binding cross-product"
LIMITS = ("Eight binary combinations of one valid allow rule and one local returning callback. "
          "No approval, provider call, delivery, arbitrary policy set, or production safety proof.")


def expected(modes):
    exact = all(value == "exact" for value in modes.values())
    return {"match": modes, "proposal": PROPOSAL_BINDINGS,
            "rule": {key: PROPOSAL_BINDINGS[key] if mode == "exact" else OTHER[key]
                     for key, mode in modes.items()},
            "receipt": {"protocol": "aml-action-dispatch/1", "proposal_sha256": DIGEST,
                        "policy_decision": "allow" if exact else "deny",
                        "execution_status": "dispatched" if exact else "blocked",
                        "reason": "host_dispatch_returned" if exact else "no_exact_rule"},
            "callback_count": 1 if exact else 0,
            "callback_target": PROPOSAL["arguments"]["to"] if exact else None}


def verify(report):
    if (set(report) != {"protocol", "provenance", "limits", "axes", "rows"}
            or report.get("protocol") != "aml-action-policy-tuple/1"
            or report.get("provenance") != PROVENANCE or report.get("limits") != LIMITS
            or report.get("axes") != AXES):
        raise ValueError("tuple provenance, protocol, scope, or axes changed")
    modes = [dict(zip(AXES, combination)) for combination in itertools.product(*AXES.values())]
    rows = report.get("rows")
    if not isinstance(rows, list) or len(rows) != 8:
        raise ValueError("tuple is missing or repeating combinations")
    for index, (mode, observed) in enumerate(zip(modes, rows)):
        wanted = expected(mode)
        if observed != wanted:
            raise ValueError(f"tuple {index} ({mode}) differs")
    return {"protocol": "aml-action-policy-tuple-oracle/1", "cases_verified": 8,
            "scope": "Project-authored local finite expectation; not an outside or formal proof"}


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("Usage: python3 verify_policy_tuple.py <report.json|->")
    data = json.load(sys.stdin if sys.argv[1] == "-" else pathlib.Path(sys.argv[1]).open(encoding="utf-8"))
    print(json.dumps(verify(data), sort_keys=True))
