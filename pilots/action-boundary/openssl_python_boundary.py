#!/usr/bin/env python3
"""Project-maintained Python/OpenSSL action case adapter; simulated callbacks only.

This implementation uses the OpenSSL command's SHA-256 rather than hashlib or
the existing Python boundary. It accepts the published restricted JSON subset.
"""
import json
from pathlib import Path
import re
import subprocess
import sys

SAFE = 2**53 - 1
EFFECTS = {"read", "write", "send", "pay", "delete"}


def canonical(value):
    if value is None or type(value) in (str, bool):
        return value
    if type(value) is int and -SAFE <= value <= SAFE:
        return value
    if type(value) is list:
        return [canonical(item) for item in value]
    if type(value) is dict and all(type(k) is str and all(ord(c) <= 0xffff for c in k) for k in value):
        def key(k):
            index = re.fullmatch(r"(0|[1-9][0-9]*)", k)
            return (0, int(k)) if index and int(k) < 2**32 - 1 else (1, k)
        return {k: canonical(value[k]) for k in sorted(value, key=key)}
    raise ValueError("unsupported_json_subset")


def wire(value):
    return json.dumps(canonical(value), ensure_ascii=False,
                      separators=(",", ":"), allow_nan=False).encode("utf-8")


def digest(value):
    return subprocess.run(["openssl", "dgst", "-sha256", "-binary"], input=wire(value),
                          capture_output=True, check=True).stdout.hex()


def plan(proposal, policy):
    proposal_digest = None
    decision, reason = "deny", "invalid_proposal"
    if (type(proposal) is dict and set(proposal) ==
            {"protocol", "tool", "effect", "resource", "purpose", "arguments"} and
            proposal["protocol"] == "aml-proposed-action/1" and
            proposal["effect"] in EFFECTS and type(proposal["arguments"]) is dict and
            all(type(proposal[k]) is str and proposal[k].strip() and
                len(proposal[k].encode("utf-16-le")) // 2 <= 256 for k in
                ("tool", "resource", "purpose")) and len(wire(proposal)) <= 65536):
        proposal_digest = digest(proposal)
        reason = "invalid_policy"
        if (type(policy) is dict and policy.get("protocol") == "aml-action-policy/1" and
                type(policy.get("rules")) is list and all(
                    type(r) is dict and set(r) ==
                    {"tool", "effect", "resource", "requires_approval"} and
                    type(r["tool"]) is str and r["tool"].strip() and
                    type(r["resource"]) is str and r["resource"].strip() and
                    r["effect"] in EFFECTS and type(r["requires_approval"]) is bool
                    for r in policy["rules"])):
            matches = [r for r in policy["rules"] if all(
                r[k] == proposal[k] for k in ("tool", "effect", "resource"))]
            if len(matches) > 1:
                reason = "ambiguous_policy"
            elif len(matches) == 0:
                reason = "no_exact_rule"
            else:
                decision = "requires_approval" if matches[0]["requires_approval"] else "allow"
                reason = "exact_rule"
        if reason in {"invalid_policy", "ambiguous_policy"}:
            proposal_digest = None
    return {"protocol": "aml-action-plan/1", "proposal_sha256": proposal_digest,
            "decision": decision, "reason": reason}


def run_case(case):
    if case.get("protocol") != "aml-action-challenge-case/1":
        raise ValueError("Unknown case protocol")
    proposal, policy, host = case["proposal"], case["policy"], case["host"]
    frozen = json.loads(wire(proposal))
    planned = plan(frozen, policy)
    status, reason, calls, executed = "blocked", planned["reason"], 0, None
    if planned["decision"] != "deny":
        if planned["decision"] == "requires_approval" and host["approval"] == "missing":
            reason = "approval_unavailable"
        elif planned["decision"] == "requires_approval" and host["approval"] == "throw":
            reason = "approval_error"
        elif (planned["decision"] == "requires_approval" and host["approval"] == "fixed" and
              host["approval_digest_sha256"] != planned["proposal_sha256"]):
            reason = "approval_missing_or_mismatched"
        elif planned["decision"] == "requires_approval" and host.get("remove_policy_rule"):
            reason = "policy_changed"
        else:
            # Host mutation occurs after the initial digest, never to frozen.
            calls, executed = 1, frozen
            status, reason = (("unknown", "host_dispatch_error") if host["tool"] == "throw"
                              else ("dispatched", "host_dispatch_returned"))
    return {"protocol": "aml-action-boundary-result/1", "plan": planned,
            "receipt": {"protocol": "aml-action-dispatch/1",
                        "proposal_sha256": planned["proposal_sha256"],
                        "policy_decision": planned["decision"],
                        "execution_status": status, "reason": reason},
            "tool_calls": calls, "executed_proposal": executed}


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("Usage: python3 openssl_python_boundary.py <case.json>")
    print(json.dumps(run_case(json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))),
                     ensure_ascii=False, separators=(",", ":")))
