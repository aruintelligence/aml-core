import test from "node:test";
import assert from "node:assert/strict";
import { createGuardedToolExecute } from "../pilots/action-boundary/guarded-tool.mjs";
import { createLocalOneShotGrants } from "../pilots/action-boundary/one-shot-grants.mjs";
import { dispatchAction, planAction } from "../pilots/action-boundary/boundary.mjs";

const proposal = { protocol: "aml-proposed-action/1", tool: "send_message", effect: "send",
  resource: "team@example.test", purpose: "Send a status update",
  arguments: { to: "team@example.test", body: "Build passed." } };
const policy = () => ({ protocol: "aml-action-policy/1", rules: [
  { tool: "send_message", effect: "send", resource: "team@example.test", requires_approval: true }
] });

test("a reused one-use grant cannot dispatch twice, including concurrent requests", async () => {
  const store = createLocalOneShotGrants();
  const grant = store.issue(planAction(proposal, policy()).proposal_sha256);
  let calls = 0;
  const guarded = createGuardedToolExecute({ tool: "send_message", effect: "send",
    purpose: "Send a status update", resourceFor: args => args.to, policy: policy(),
    requestApproval: async () => grant, consumeApproval: store.consume,
    execute: async () => { calls++; return "fixture only"; } });
  const outcomes = await Promise.all([guarded(proposal.arguments), guarded(proposal.arguments)]);
  assert.deepEqual(outcomes.map(x => x.receipt.execution_status).sort(), ["blocked", "dispatched"]);
  assert.equal(outcomes.find(x => x.receipt.execution_status === "blocked").receipt.reason,
    "approval_reused_or_expired");
  assert.equal(calls, 1);
  assert.equal((await guarded(proposal.arguments)).receipt.reason, "approval_reused_or_expired");
  assert.equal(calls, 1);
});

test("an expired, changed, or unknown grant is blocked before the callback", async () => {
  let clock = 1000;
  const store = createLocalOneShotGrants({ now: () => clock });
  const digest = planAction(proposal, policy()).proposal_sha256;
  const grant = store.issue(digest, { ttlMs: 100 });
  let calls = 0;
  const options = { policy: policy(), requestApproval: async () => grant,
    consumeApproval: store.consume, executeTool: async () => { calls++; } };
  clock = 1100;
  assert.equal((await dispatchAction(proposal, options)).receipt.reason, "approval_reused_or_expired");
  assert.equal(calls, 0);

  const fresh = store.issue(digest);
  const changed = { ...proposal, arguments: { ...proposal.arguments, body: "Changed" } };
  assert.equal((await dispatchAction(changed, { ...options, requestApproval: async () => fresh })).receipt.reason,
    "approval_missing_or_mismatched");
  assert.equal((await dispatchAction(proposal, { ...options,
    requestApproval: async () => ({ ...fresh, approval_id: "unknown" }) })).receipt.reason,
    "approval_reused_or_expired");
  assert.equal(calls, 0);
});

test("a grant stays spent after an uncertain tool result", async () => {
  const store = createLocalOneShotGrants();
  const grant = store.issue(planAction(proposal, policy()).proposal_sha256);
  let calls = 0;
  const options = { policy: policy(), requestApproval: async () => grant,
    consumeApproval: store.consume, executeTool: async () => { calls++; throw Error("unknown result"); } };
  assert.equal((await dispatchAction(proposal, options)).receipt.execution_status, "unknown");
  assert.equal((await dispatchAction(proposal, options)).receipt.reason, "approval_reused_or_expired");
  assert.equal(calls, 1);
});

test("revocation while an asynchronous claim runs still blocks dispatch", async () => {
  const mutable = policy();
  const store = createLocalOneShotGrants();
  const grant = store.issue(planAction(proposal, mutable).proposal_sha256);
  let calls = 0;
  const result = await dispatchAction(proposal, { policy: mutable,
    requestApproval: async () => grant,
    consumeApproval: async input => { const claimed = store.consume(input); mutable.rules.length = 0; return claimed; },
    executeTool: async () => { calls++; } });
  assert.equal(result.receipt.reason, "policy_changed");
  assert.equal(calls, 0);
  assert.equal(store.consume({ approval: grant, proposal_sha256: grant.proposal_sha256 }), false);
});
