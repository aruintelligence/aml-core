#!/usr/bin/env python3
"""Project-maintained Python black-box adapter for the published 13 cases."""

import asyncio
import json
from pathlib import Path
import sys

from python_boundary import dispatch_action, plan_action


async def run_case(data):
    if data.get("protocol") != "aml-action-challenge-case/1":
        raise ValueError("Unknown case protocol")
    # A JSON round trip makes independent mutable host inputs. The boundary
    # itself freezes its proposal before yielding to approval.
    proposal = json.loads(json.dumps(data["proposal"]))
    policy = json.loads(json.dumps(data["policy"]))
    host = data["host"]
    plan = plan_action(proposal, policy)
    tool_calls = 0
    executed_proposal = None

    async def request_approval(input_data):
        if host.get("mutate_proposal_body"):
            proposal["arguments"]["body"] = host["mutate_proposal_body"]
            input_data["proposal"]["arguments"]["body"] = host["mutate_proposal_body"]
        if host.get("remove_policy_rule"):
            policy["rules"].clear()
        if host["approval"] == "throw":
            raise RuntimeError("Simulated approval failure")
        return {"approved": True, "proposal_sha256":
                host["approval_digest_sha256"] if host["approval"] == "fixed"
                else input_data["proposal_sha256"]}

    async def execute_tool(frozen):
        nonlocal tool_calls, executed_proposal
        tool_calls += 1
        executed_proposal = frozen
        if host["tool"] == "throw":
            raise RuntimeError("Simulated callback uncertainty")
        return {"simulated": True}

    outcome = await dispatch_action(proposal, policy=policy,
                                    request_approval=None if host["approval"] == "missing"
                                    else request_approval,
                                    execute_tool=execute_tool)
    return {"protocol": "aml-action-boundary-result/1", "plan": plan,
            "receipt": outcome["receipt"], "tool_calls": tool_calls,
            "executed_proposal": executed_proposal}


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 challenge-python-adapter.py <case.json>", file=sys.stderr)
        sys.exit(2)
    print(json.dumps(asyncio.run(run_case(json.loads(Path(sys.argv[1]).read_text(encoding="utf-8")))),
                     ensure_ascii=False, separators=(",", ":")))
