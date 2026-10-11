"""Narrow Python-specific failure and callback tests beyond the shared 13 cases."""

import asyncio
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "pilots" / "action-boundary"))
from python_boundary import dispatch_action, plan_action  # noqa: E402


def fixture():
    proposal = {"protocol": "aml-proposed-action/1", "tool": "send_message",
                "effect": "send", "resource": "team@example.test", "purpose": "Status",
                "arguments": {"body": "Original"}}
    policy = {"protocol": "aml-action-policy/1", "rules": [
        {"tool": "send_message", "effect": "send", "resource": "team@example.test",
         "requires_approval": True}]}
    return proposal, policy


class PythonBoundaryTests(unittest.TestCase):
    def test_unsupported_cross_language_values_fail_closed(self):
        proposal, policy = fixture()
        proposal["arguments"]["fraction"] = 1.5
        self.assertEqual(plan_action(proposal, policy)["reason"], "unsupported_json_subset")
        proposal, policy = fixture()
        proposal["arguments"]["😀"] = 1
        self.assertEqual(plan_action(proposal, policy)["reason"], "unsupported_json_subset")
        proposal, policy = fixture()
        proposal["effect"] = {"invalid": True}
        self.assertEqual(plan_action(proposal, policy)["reason"], "invalid_proposal")
        proposal, policy = fixture()
        policy["rules"][0]["effect"] = ["send"]
        self.assertEqual(plan_action(proposal, policy)["reason"], "invalid_policy")

    def test_consume_and_policy_recheck(self):
        proposal, policy = fixture()
        calls = []

        async def approve(input_data):
            proposal["arguments"]["body"] = "Changed after approval started"
            return {"approved": True, "proposal_sha256": input_data["proposal_sha256"]}

        async def consume(input_data):
            self.assertEqual(input_data["proposal"]["arguments"]["body"], "Original")
            policy["rules"].clear()
            return True

        async def execute(frozen):
            calls.append(frozen)

        result = asyncio.run(dispatch_action(proposal, policy=policy,
                                             request_approval=approve,
                                             consume_approval=consume,
                                             execute_tool=execute))
        self.assertEqual(result["receipt"]["reason"], "policy_changed")
        self.assertEqual(calls, [])

    def test_failed_claim_never_calls_tool(self):
        proposal, policy = fixture()
        calls = []

        async def approve(input_data):
            return {"approved": True, "proposal_sha256": input_data["proposal_sha256"]}

        async def consume(_):
            return False

        async def execute(frozen):
            calls.append(frozen)

        result = asyncio.run(dispatch_action(proposal, policy=policy,
                                             request_approval=approve,
                                             consume_approval=consume,
                                             execute_tool=execute))
        self.assertEqual(result["receipt"]["reason"], "approval_reused_or_expired")
        self.assertEqual(calls, [])

    def test_invalid_host_callbacks_fail_closed(self):
        proposal, policy = fixture()

        async def approve(input_data):
            return {"approved": True, "proposal_sha256": input_data["proposal_sha256"]}

        async def execute(_):
            self.fail("Tool should not run")

        result = asyncio.run(dispatch_action(proposal, policy=policy,
                                             request_approval=approve,
                                             consume_approval="not a callback",
                                             execute_tool=execute))
        self.assertEqual(result["receipt"]["reason"], "invalid_host_consumer")


if __name__ == "__main__":
    unittest.main()
