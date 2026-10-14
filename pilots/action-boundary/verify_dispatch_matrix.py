#!/usr/bin/env python3
"""Independent, bounded oracle for dispatch-matrix.mjs observations."""
import hashlib
import itertools
import json
import pathlib
import sys

AXES = {
    "policy": ["deny", "allow", "requires_approval", "ambiguous"],
    "approval": ["match", "decline", "mismatch", "throw", "revoke", "mutate_caller"],
    "claim": ["accept", "refuse", "throw_after_consume", "revoke_after_consume"],
    "callback": ["return", "throw_after_write"],
}
PROPOSAL = {
    "protocol": "aml-proposed-action/1", "tool": "send_message", "effect": "send",
    "resource": "team@example.test", "purpose": "Matrix local callback",
    "arguments": {"to": "team@example.test", "body": "Build passed."},
}
DIGEST = hashlib.sha256(json.dumps(PROPOSAL, sort_keys=True, separators=(",", ":"),
                                   ensure_ascii=False).encode("utf-8")).hexdigest()


def expected(policy, approval, claim, callback):
    requests = attempts = consumed = callbacks = writes = 0
    target = result = None
    caller = "team@example.test"
    decision = "deny" if policy in ("deny", "ambiguous") else (
        "allow" if policy == "allow" else "requires_approval")
    digest = None if policy == "ambiguous" else DIGEST

    if policy == "deny":
        status, reason = "blocked", "no_exact_rule"
    elif policy == "ambiguous":
        status, reason = "blocked", "ambiguous_policy"
    else:
        if policy == "requires_approval":
            requests = 1
            if approval == "mutate_caller":
                caller = "other@example.test"
            if approval == "throw":
                status, reason = "blocked", "approval_error"
            elif approval in ("decline", "mismatch"):
                status, reason = "blocked", "approval_missing_or_mismatched"
            elif approval == "revoke":
                status, reason = "blocked", "policy_changed"
            else:
                attempts = 1
                if claim == "refuse":
                    status, reason = "blocked", "approval_reused_or_expired"
                else:
                    consumed = 1
                    if claim == "throw_after_consume":
                        status, reason = "blocked", "approval_consume_error"
                    elif claim == "revoke_after_consume":
                        status, reason = "blocked", "policy_changed"
                    else:
                        status = None
        else:
            status = None
        if status is None:
            callbacks = 1
            target = "team@example.test"
            if callback == "throw_after_write":
                writes = 1
                status, reason = "unknown", "host_dispatch_error"
            else:
                result = target
                status, reason = "dispatched", "host_dispatch_returned"

    return {
        "policy": policy, "approval": approval, "claim": claim, "callback": callback,
        "receipt": {"protocol": "aml-action-dispatch/1", "proposal_sha256": digest,
                    "policy_decision": decision, "execution_status": status, "reason": reason},
        "approval_requests": requests, "claim_attempts": attempts,
        "claims_consumed": consumed, "callback_count": callbacks,
        "fixture_writes": writes, "callback_target": target,
        "caller_target_after": caller, "result_target": result,
    }


def verify(report):
    if (set(report) != {"protocol", "provenance", "limits", "axes", "rows"}
            or report.get("protocol") != "aml-action-dispatch-matrix/1"
            or report.get("provenance") != "project-authored bounded cross-product of local callbacks"
            or report.get("limits") != "192 finite combinations. No human approval, provider call, delivery, arbitrary interleaving, or production safety proof."
            or report.get("axes") != AXES):
        raise ValueError("matrix provenance, scope, protocol, or finite axes changed")
    vectors = list(itertools.product(*(AXES[key] for key in AXES)))
    rows = report.get("rows")
    if not isinstance(rows, list) or len(rows) != len(vectors):
        raise ValueError("matrix is missing or repeating vectors")
    for index, ((policy, approval, claim, callback), observed) in enumerate(zip(vectors, rows)):
        wanted = expected(policy, approval, claim, callback)
        if observed != wanted:
            difference = [key for key in wanted if observed.get(key) != wanted[key]]
            raise ValueError(f"vector {index} ({policy}/{approval}/{claim}/{callback}) differs: {difference}")
    return {"protocol": "aml-action-dispatch-matrix-oracle/1", "vectors_verified": len(vectors),
            "oracle": "Python finite state expectation independent of the Node callback implementation",
            "scope": "Finite project-authored local fixtures; no formal, independent, or production proof"}


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("Usage: python3 verify_dispatch_matrix.py <report.json|->")
    data = json.load(sys.stdin if sys.argv[1] == "-" else pathlib.Path(sys.argv[1]).open(encoding="utf-8"))
    print(json.dumps(verify(data), sort_keys=True))
