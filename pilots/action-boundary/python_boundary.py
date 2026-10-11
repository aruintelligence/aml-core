"""Dependency-free Python implementation of the public action-boundary subset.

This module does not import or call the JavaScript reference. Its wire subset
accepts JSON integers in the JS safe range, BMP object keys, and Unicode-scalar
string values. Floats, non-BMP object keys, and lone surrogate values are
rejected rather than pretending to be canonical across languages. It
authenticates nobody and runs no tool unless the host supplies a callback.
Project-maintained code is not an independent external witness.
"""

import hashlib
import json
import re

EFFECTS = {"read", "write", "send", "pay", "delete"}
PROPOSAL_KEYS = {"protocol", "tool", "effect", "resource", "purpose", "arguments"}
RULE_KEYS = {"tool", "effect", "resource", "requires_approval"}
SAFE_INTEGER = 2**53 - 1


def _js_array_index(key):
    """ECMAScript ordinary object array index: 0..2^32-2, canonical digits."""
    if (len(key) > 10 or re.fullmatch(r"(0|[1-9][0-9]*)", key) is None):
        return None
    index = int(key)
    return index if index < 2**32 - 1 else None


def _js_object_key_order(keys):
    # The JS reference sorts keys, rebuilds an ordinary object with
    # Object.fromEntries, then JSON.stringify enumerates array indices first.
    indices = [key for key in keys if _js_array_index(key) is not None]
    others = [key for key in keys if _js_array_index(key) is None]
    return sorted(indices, key=int) + sorted(others)


def _canonical_subset(value):
    if value is None or type(value) in (bool, str):
        return value
    if type(value) is int and -SAFE_INTEGER <= value <= SAFE_INTEGER:
        return value
    if type(value) is list:
        return [_canonical_subset(item) for item in value]
    if type(value) is dict and all(type(key) is str and
                                    all(ord(char) <= 0xFFFF for char in key)
                                    for key in value):
        return {key: _canonical_subset(value[key]) for key in _js_object_key_order(value)}
    raise ValueError("unsupported_json_subset")


def _snapshot(proposal):
    if (type(proposal) is not dict or set(proposal) != PROPOSAL_KEYS
            or proposal["protocol"] != "aml-proposed-action/1"
            or type(proposal["effect"]) is not str or proposal["effect"] not in EFFECTS
            or type(proposal["arguments"]) is not dict
            or any(type(proposal[key]) is not str or not proposal[key].strip()
                   or len(proposal[key].encode("utf-16-le", "surrogatepass")) // 2 > 256
                   for key in ("tool", "resource", "purpose"))):
        raise ValueError("invalid_proposal")
    try:
        wire = json.dumps(_canonical_subset(proposal), ensure_ascii=False,
                          separators=(",", ":"), allow_nan=False).encode("utf-8")
    except UnicodeError as error:
        raise ValueError("unsupported_json_subset") from error
    if len(wire) > 65536:
        raise ValueError("proposal_too_large")
    return wire, hashlib.sha256(wire).hexdigest(), json.loads(wire)


def _rule_for(proposal, policy):
    if (type(policy) is not dict or policy.get("protocol") != "aml-action-policy/1"
            or type(policy.get("rules")) is not list):
        raise ValueError("invalid_policy")
    for rule in policy["rules"]:
        if (type(rule) is not dict or set(rule) != RULE_KEYS
                or type(rule["effect"]) is not str or rule["effect"] not in EFFECTS
                or any(type(rule[key]) is not str or not rule[key].strip()
                       for key in ("tool", "resource"))
                or type(rule["requires_approval"]) is not bool):
            raise ValueError("invalid_policy")
    matches = [rule for rule in policy["rules"]
               if all(rule[key] == proposal[key] for key in ("tool", "effect", "resource"))]
    if len(matches) > 1:
        raise ValueError("ambiguous_policy")
    return matches[0] if matches else None


def plan_action(proposal, policy):
    try:
        _, digest, frozen = _snapshot(proposal)
        rule = _rule_for(frozen, policy)
        return {"protocol": "aml-action-plan/1", "proposal_sha256": digest,
                "decision": "deny" if rule is None else
                            "requires_approval" if rule["requires_approval"] else "allow",
                "reason": "exact_rule" if rule else "no_exact_rule"}
    except ValueError as error:
        return {"protocol": "aml-action-plan/1", "proposal_sha256": None,
                "decision": "deny", "reason": str(error)}


async def dispatch_action(proposal, *, policy, request_approval=None,
                          consume_approval=None, execute_tool=None):
    plan = plan_action(proposal, policy)

    def receipt(status, reason):
        return {"protocol": "aml-action-dispatch/1",
                "proposal_sha256": plan["proposal_sha256"],
                "policy_decision": plan["decision"],
                "execution_status": status, "reason": reason}

    if plan["decision"] == "deny":
        return {"receipt": receipt("blocked", plan["reason"])}
    if not callable(execute_tool):
        return {"receipt": receipt("blocked", "missing_host_dispatch")}
    wire, digest, frozen = _snapshot(proposal)
    approval = None
    if plan["decision"] == "requires_approval":
        if not callable(request_approval):
            return {"receipt": receipt("blocked", "approval_unavailable")}
        try:
            approval = await request_approval({"proposal": json.loads(wire),
                                               "proposal_sha256": digest})
        except Exception:
            return {"receipt": receipt("blocked", "approval_error")}
        if (type(approval) is not dict or approval.get("approved") is not True
                or approval.get("proposal_sha256") != digest):
            return {"receipt": receipt("blocked", "approval_missing_or_mismatched")}

    rechecked = plan_action(frozen, policy)
    if rechecked["decision"] != plan["decision"] or rechecked["proposal_sha256"] != digest:
        return {"receipt": receipt("blocked", "policy_changed")}
    if plan["decision"] == "requires_approval" and consume_approval is not None:
        if not callable(consume_approval):
            return {"receipt": receipt("blocked", "invalid_host_consumer")}
        try:
            consumed = await consume_approval({"approval": approval,
                                               "proposal": json.loads(wire),
                                               "proposal_sha256": digest})
        except Exception:
            return {"receipt": receipt("blocked", "approval_consume_error")}
        if consumed is not True:
            return {"receipt": receipt("blocked", "approval_reused_or_expired")}
        final = plan_action(frozen, policy)
        if final["decision"] != plan["decision"] or final["proposal_sha256"] != digest:
            return {"receipt": receipt("blocked", "policy_changed")}
    try:
        result = await execute_tool(json.loads(wire))
        return {"receipt": receipt("dispatched", "host_dispatch_returned"), "result": result}
    except Exception:
        return {"receipt": receipt("unknown", "host_dispatch_error")}
