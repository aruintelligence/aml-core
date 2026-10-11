#!/usr/bin/env python3
"""Independent, dependency-free verifier for the published action vectors.

This covers the JSON subset in vectors.json; it does not implement JavaScript's
full number formatting or UTF-16 key ordering for arbitrary inputs.
"""
import hashlib
import json
from pathlib import Path
import sys

EFFECTS = {"read", "write", "send", "pay", "delete"}
PROPOSAL_KEYS = {"protocol", "tool", "effect", "resource", "purpose", "arguments"}
RULE_KEYS = {"tool", "effect", "resource", "requires_approval"}


def plan(proposal, policy):
    if (not isinstance(proposal, dict) or set(proposal) != PROPOSAL_KEYS
            or proposal["protocol"] != "aml-proposed-action/1"
            or proposal["effect"] not in EFFECTS
            or not isinstance(proposal["arguments"], dict)
            or any(not isinstance(proposal[k], str) or not proposal[k].strip()
                   or len(proposal[k]) > 256 for k in ("tool", "resource", "purpose"))):
        raise ValueError("invalid proposal")
    canonical = json.dumps(proposal, sort_keys=True, ensure_ascii=False,
                           separators=(",", ":"), allow_nan=False).encode("utf-8")
    if len(canonical) > 65536:
        raise ValueError("proposal too large")
    digest = hashlib.sha256(canonical).hexdigest()
    if (not isinstance(policy, dict) or policy.get("protocol") != "aml-action-policy/1"
            or not isinstance(policy.get("rules"), list)):
        raise ValueError("invalid policy")
    for rule in policy["rules"]:
        if (not isinstance(rule, dict) or set(rule) != RULE_KEYS
                or rule["effect"] not in EFFECTS
                or any(not isinstance(rule[k], str) or not rule[k].strip()
                       for k in ("tool", "resource"))
                or type(rule["requires_approval"]) is not bool):
            raise ValueError("invalid rule")
    matches = [rule for rule in policy["rules"]
               if all(rule[k] == proposal[k] for k in ("tool", "effect", "resource"))]
    if len(matches) > 1:
        raise ValueError("ambiguous policy")
    if not matches:
        return digest, "deny", "no_exact_rule"
    return digest, ("requires_approval" if matches[0]["requires_approval"] else "allow"), "exact_rule"


def verify(data):
    if data.get("protocol") != "aml-action-vectors/1":
        raise ValueError("unknown vector protocol")
    for case in data["cases"]:
        actual = plan(case["proposal"], data["policy"])
        expected = (case["proposal_sha256"], case["decision"], case["reason"])
        if actual != expected:
            raise ValueError(f'{case["name"]}: expected {expected}, got {actual}')
    return len(data["cases"])


if __name__ == "__main__":
    source = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).with_name("vectors.json")
    try:
        data = json.loads(source.read_text(encoding="utf-8"))
        count = verify(data)
        # A changed action with a stale expected digest must fail independently.
        changed = json.loads(json.dumps(data))
        changed["cases"][0]["proposal"]["arguments"]["body"] = "Tampered"
        try:
            verify(changed)
        except ValueError:
            pass
        else:
            raise ValueError("tamper was not detected")
        print(f"Verified {count} action vectors and rejected a tamper")
    except (ValueError, KeyError, TypeError) as error:
        print(f"Verification failed: {error}", file=sys.stderr)
        sys.exit(1)
