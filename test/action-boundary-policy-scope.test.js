import test from "node:test";
import assert from "node:assert/strict";
import { planAction, dispatchAction } from "../pilots/action-boundary/boundary.mjs";

const original = { protocol: "aml-proposed-action/1", tool: "send_message",
  effect: "send", resource: "team@example.test", purpose: "Send update",
  arguments: { to: "team@example.test", body: "Approved text" } };
const changed = { ...original, arguments: { ...original.arguments, body: "Different text" } };
const policy = requires_approval => ({ protocol: "aml-action-policy/1", rules: [
  { tool: "send_message", effect: "send", resource: "team@example.test", requires_approval }
] });

test("a same-destination body change still matches an unreviewed tuple rule", async () => {
  const baseline = planAction(original, policy(false));
  const altered = planAction(changed, policy(false));
  assert.equal(baseline.decision, "allow");
  assert.equal(altered.decision, "allow");
  assert.notEqual(baseline.proposal_sha256, altered.proposal_sha256);
  let calls = 0;
  const result = await dispatchAction(changed, { policy: policy(false),
    executeTool: async () => { calls++; return { simulated: true }; } });
  assert.equal(result.receipt.execution_status, "dispatched");
  assert.equal(calls, 1);
});

test("a fixed host digest rejects the changed body before a callback", async () => {
  const originalDigest = planAction(original, policy(true)).proposal_sha256;
  let calls = 0;
  const options = { policy: policy(true),
    requestApproval: async () => ({ approved: true, proposal_sha256: originalDigest }),
    executeTool: async () => { calls++; return { simulated: true }; } };
  const allowed = await dispatchAction(original, options);
  const blocked = await dispatchAction(changed, options);
  assert.equal(allowed.receipt.execution_status, "dispatched");
  assert.deepEqual([blocked.receipt.execution_status, blocked.receipt.reason],
    ["blocked", "approval_missing_or_mismatched"]);
  assert.equal(calls, 1);
});
