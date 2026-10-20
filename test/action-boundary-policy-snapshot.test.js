import test from "node:test";
import assert from "node:assert/strict";
import { planAction, dispatchAction } from "../pilots/action-boundary/boundary.mjs";
import { createGuardedToolExecute } from "../pilots/action-boundary/guarded-tool.mjs";
import { createMailGuardedToolExecute } from "../pilots/action-boundary/mail-guarded-tool.mjs";
import { mailTargetResource } from "../pilots/action-boundary/mail-target-manifest.mjs";

const proposal = { protocol: "aml-proposed-action/1", tool: "send_message",
  effect: "send", resource: "team@example.test", purpose: "Send update",
  arguments: { to: "team@example.test", body: "Approved text" } };

function changingPolicy(field, first, later) {
  let reads = 0;
  const rule = { tool: "send_message", effect: "send",
    resource: "team@example.test", requires_approval: true };
  Object.defineProperty(rule, field, { enumerable: true, get() {
    return ++reads === 1 ? first : later;
  } });
  return { policy: { protocol: "aml-action-policy/1", rules: [rule] },
    reads: () => reads };
}

test("a stateful approval flag cannot turn an approval rule into unreviewed dispatch", async () => {
  const live = changingPolicy("requires_approval", true, false);
  let calls = 0;
  const outcome = await dispatchAction(proposal, { policy: live.policy,
    executeTool: async () => { calls++; } });
  assert.equal(outcome.receipt.execution_status, "blocked");
  assert.equal(outcome.receipt.reason, "approval_unavailable");
  assert.equal(outcome.receipt.policy_decision, "requires_approval");
  assert.equal(live.reads(), 1);
  assert.equal(calls, 0);

  const planned = changingPolicy("requires_approval", true, false);
  assert.equal(planAction(proposal, planned.policy).decision, "requires_approval");
  assert.equal(planned.reads(), 1);
});

test("a changing resource cannot match a rule after a different value was checked", async () => {
  const live = changingPolicy("resource", "other@example.test", "team@example.test");
  let calls = 0;
  const outcome = await dispatchAction(proposal, { policy: live.policy,
    executeTool: async () => { calls++; } });
  assert.deepEqual([outcome.receipt.execution_status, outcome.receipt.reason, live.reads(), calls],
    ["blocked", "no_exact_rule", 1, 0]);

  const checked = changingPolicy("resource", "other@example.test", "team@example.test");
  assert.deepEqual([planAction(proposal, checked.policy).decision, checked.reads()], ["deny", 1]);
});

test("a guarded tool reports the plan from its dispatch rather than an earlier policy read", async () => {
  const changing = changingPolicy("requires_approval", true, false);
  let calls = 0;
  const guarded = createGuardedToolExecute({ tool: "send_message", effect: "send",
    purpose: "Send update", resourceFor: args => args.to, policy: changing.policy,
    execute: async () => { calls++; } });
  const outcome = await guarded({ to: "team@example.test", body: "Approved text" });
  assert.equal(outcome.plan.decision, outcome.receipt.policy_decision);
  assert.equal(outcome.plan.proposal_sha256, outcome.receipt.proposal_sha256);
  assert.equal(outcome.receipt.reason, "approval_unavailable");
  assert.equal(calls, 0);
});

test("a mail guard reports the plan from its target-bound dispatch", async () => {
  const args = { to: "team@example.test", subject: "Release", body: "Ready." };
  const resource = mailTargetResource(args).resource;
  const rule = { tool: "send_message", effect: "send", resource,
    requires_approval: false };
  let reads = 0, calls = 0;
  Object.defineProperty(rule, "resource", { enumerable: true, get() {
    return ++reads === 1 ? "other@example.test" : resource;
  } });
  const guarded = createMailGuardedToolExecute({ purpose: "Send release",
    policy: { protocol: "aml-action-policy/1", rules: [rule] },
    execute: async () => { calls++; } });
  const outcome = await guarded(args);
  assert.equal(outcome.plan.decision, outcome.receipt.policy_decision);
  assert.equal(outcome.plan.proposal_sha256, outcome.receipt.proposal_sha256);
  assert.equal(outcome.receipt.reason, "no_exact_rule");
  assert.equal(calls, 0);
});
