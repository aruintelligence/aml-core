import test from "node:test";
import assert from "node:assert/strict";
import { PROTOCOL, planAction, dispatchAction } from "./boundary.mjs";

const proposal = { protocol: PROTOCOL, tool: "send_message", effect: "send",
  resource: "team@example.test", purpose: "Send a status update", arguments: { body: "Hello", subject: "Update" } };
const policy = { protocol: "aml-action-policy/1", rules: [
  { tool: "send_message", effect: "send", resource: "team@example.test", requires_approval: true }
] };

test("exact match needs approval and reordered arguments retain the same digest", () => {
  const plan = planAction(proposal, policy);
  assert.equal(plan.decision, "requires_approval");
  assert.equal(plan.proposal_sha256, planAction({ ...proposal, arguments: { subject: "Update", body: "Hello" } }, policy).proposal_sha256);
  assert.equal(planAction({ ...proposal, resource: "other@example.test" }, policy).decision, "deny");
  assert.equal(planAction({ ...proposal, effect: "delete" }, policy).decision, "deny");
});

test("approval binds the exact proposal, including arguments", async () => {
  let calls = 0;
  const blocked = await dispatchAction(proposal, { policy, requestApproval: async () => ({ approved: true,
    proposal_sha256: "0".repeat(64) }), executeTool: async () => { calls++; } });
  assert.equal(blocked.receipt.execution_status, "blocked");
  assert.equal(calls, 0);
  const allowed = await dispatchAction(proposal, { policy, requestApproval: async ({ proposal_sha256 }) =>
    ({ approved: true, proposal_sha256 }), executeTool: async frozen => { calls++; return frozen.arguments.body; } });
  assert.equal(allowed.receipt.execution_status, "dispatched");
  assert.equal(allowed.result, "Hello");
  assert.equal(calls, 1);
});

test("mutation during approval cannot alter dispatched bytes", async () => {
  const original = structuredClone(proposal);
  const seen = [];
  await dispatchAction(original, { policy, requestApproval: async ({ proposal: copy, proposal_sha256 }) => {
    original.arguments.body = "MUTATED";
    copy.arguments.body = "MUTATED";
    return { approved: true, proposal_sha256 };
  }, executeTool: async frozen => { seen.push(frozen.arguments.body); } });
  assert.deepEqual(seen, ["Hello"]);
});

test("invalid or ambiguous policies fail closed; dispatch error is unknown", async () => {
  assert.equal(planAction(proposal, { ...policy, rules: [...policy.rules, ...policy.rules] }).reason, "ambiguous_policy");
  assert.equal(planAction({ ...proposal, extra: true }, policy).decision, "deny");
  assert.equal(planAction({ ...proposal, arguments: { body: () => true } }, policy).decision, "deny");
  const unknown = await dispatchAction(proposal, { policy, requestApproval: async ({ proposal_sha256 }) =>
    ({ approved: true, proposal_sha256 }), executeTool: async () => { throw new Error("timeout"); } });
  assert.equal(unknown.receipt.execution_status, "unknown");
});

test("missing approval and policy changes during approval block dispatch", async () => {
  let calls = 0;
  assert.equal((await dispatchAction(proposal, { policy, executeTool: async () => { calls++; } })).receipt.reason,
    "approval_unavailable");
  const mutablePolicy = structuredClone(policy);
  const changed = await dispatchAction(proposal, { policy: mutablePolicy,
    requestApproval: async ({ proposal_sha256 }) => {
      mutablePolicy.rules.length = 0;
      return { approved: true, proposal_sha256 };
    }, executeTool: async () => { calls++; } });
  assert.equal(changed.receipt.reason, "policy_changed");
  assert.equal(calls, 0);
});

test("explicit read rule can dispatch without approval", async () => {
  const read = { ...proposal, tool: "fetch_record", effect: "read", resource: "record:example" };
  const readPolicy = { protocol: "aml-action-policy/1", rules: [
    { tool: "fetch_record", effect: "read", resource: "record:example", requires_approval: false }
  ] };
  const outcome = await dispatchAction(read, { policy: readPolicy, executeTool: async () => "sample" });
  assert.equal(outcome.receipt.execution_status, "dispatched");
  assert.equal(outcome.result, "sample");
});
