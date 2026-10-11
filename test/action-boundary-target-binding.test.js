import test from "node:test";
import assert from "node:assert/strict";
import { dispatchAction, planAction } from "../pilots/action-boundary/boundary.mjs";
import { dispatchTargetBoundAction } from "../pilots/action-boundary/target-boundary.mjs";

const original = () => ({ protocol: "aml-proposed-action/1", tool: "send_message",
  effect: "send", resource: "team@example.test", purpose: "Send the release update",
  arguments: { to: "team@example.test", body: "The release is ready." } });
const policy = requires_approval => ({ protocol: "aml-action-policy/1", rules: [
  { tool: "send_message", effect: "send", resource: "team@example.test", requires_approval }
] });
const recipient = ({ tool, effect, arguments: args }) => {
  if (tool !== "send_message" || effect !== "send") throw Error("unsupported tool");
  return args.to;
};

test("a forged declared resource reaches the old callback but fails target binding", async () => {
  const forged = original(); forged.arguments.to = "outside@example.test";
  const oldCalls = [], boundCalls = [];
  const old = await dispatchAction(forged, { policy: policy(false),
    executeTool: async value => { oldCalls.push(value.arguments.to); } });
  const bound = await dispatchTargetBoundAction(forged, { policy: policy(false), resolveTarget: recipient,
    executeTool: async value => { boundCalls.push(value.arguments.to); } });
  assert.equal(planAction(forged, policy(false)).decision, "allow");
  assert.equal(old.receipt.execution_status, "dispatched");
  assert.deepEqual(oldCalls, ["outside@example.test"]);
  assert.deepEqual([bound.receipt.execution_status, bound.receipt.reason], ["blocked", "target_mismatch"]);
  assert.equal(bound.receipt.proposal_sha256, old.receipt.proposal_sha256);
  assert.deepEqual(boundCalls, []);
});

test("aligned target dispatches a frozen proposal and a body change remains in host scope", async () => {
  const input = original(), calls = [];
  input.arguments.body = "Different text";
  const result = await dispatchTargetBoundAction(input, { policy: policy(false),
    resolveTarget: async ({ arguments: args }) => {
      input.arguments.to = "outside@example.test";
      args.to = "outside@example.test";
      return "team@example.test";
    }, executeTool: async value => { calls.push(value); } });
  assert.equal(result.receipt.execution_status, "dispatched");
  assert.deepEqual(calls.map(value => value.arguments),
    [{ to: "team@example.test", body: "Different text" }]);
});

test("missing, failed, or mismatched resolver blocks before approval and callback", async () => {
  const cases = [
    [undefined, "target_resolver_unavailable"],
    [() => undefined, "target_unavailable"],
    [() => { throw Error("resolver down"); }, "target_resolution_error"],
    [() => "outside@example.test", "target_mismatch"]
  ];
  for (const [resolveTarget, reason] of cases) {
    let approvals = 0, calls = 0;
    const result = await dispatchTargetBoundAction(original(), { policy: policy(true), resolveTarget,
      requestApproval: async () => { approvals++; return { approved: true }; },
      executeTool: async () => { calls++; } });
    assert.deepEqual([result.receipt.execution_status, result.receipt.reason], ["blocked", reason]);
    assert.equal(approvals, 0, reason); assert.equal(calls, 0, reason);
  }
});

test("matching targets still obey digest approval and uncertain callback handling", async () => {
  const proposal = original();
  const staleDigest = planAction({ ...proposal, purpose: "Different purpose" }, policy(true)).proposal_sha256;
  let calls = 0;
  const stale = await dispatchTargetBoundAction(proposal, { policy: policy(true), resolveTarget: recipient,
    requestApproval: async () => ({ approved: true, proposal_sha256: staleDigest }),
    executeTool: async () => { calls++; } });
  assert.equal(stale.receipt.reason, "approval_missing_or_mismatched");
  assert.equal(calls, 0);
  const uncertain = await dispatchTargetBoundAction(proposal, { policy: policy(false), resolveTarget: recipient,
    executeTool: async () => { calls++; throw Error("transport uncertainty"); } });
  assert.deepEqual([uncertain.receipt.execution_status, uncertain.receipt.reason],
    ["unknown", "host_dispatch_error"]);
  assert.equal(calls, 1);
});

test("a changed declared resource or invalid proposal never resolves or dispatches", async () => {
  let resolutions = 0, calls = 0;
  const host = { policy: policy(false), resolveTarget: () => { resolutions++; return "team@example.test"; },
    executeTool: async () => { calls++; } };
  const changed = original(); changed.resource = "outside@example.test";
  const denied = await dispatchTargetBoundAction(changed, host);
  const invalid = await dispatchTargetBoundAction({ ...original(), effect: "explode" }, host);
  assert.equal(denied.receipt.reason, "no_exact_rule");
  assert.equal(invalid.receipt.reason, "invalid_proposal");
  assert.equal(resolutions, 0); assert.equal(calls, 0);
});
