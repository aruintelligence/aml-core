import test from "node:test";
import assert from "node:assert/strict";
import { createGuardedToolExecute } from "../pilots/action-boundary/guarded-tool.mjs";

const route = "team@example.test";
const policy = () => ({ protocol: "aml-action-policy/1", rules: [
  { tool: "send_message", effect: "send", resource: route, requires_approval: true }
] });
const makeTool = (overrides = {}) => createGuardedToolExecute({
  tool: "send_message", effect: "send", purpose: "Send a status update",
  resourceFor: args => args.to, policy: policy(),
  requestApproval: async ({ proposal_sha256 }) => ({ approved: true, proposal_sha256 }),
  execute: async args => ({ to: args.to, body: args.body }), ...overrides
});

test("the adapter routes a permitted proposal and returns the exact receipt", async () => {
  let count = 0;
  const context = { host_user: "demo" };
  const guarded = makeTool({ execute: async (args, seenContext, frozen) => {
    count++;
    assert.equal(seenContext, context);
    assert.equal(frozen.resource, route);
    return { body: args.body };
  } });
  const result = await guarded({ to: route, body: "Build passed." }, context);
  assert.equal(count, 1);
  assert.equal(result.protocol, "aml-guarded-tool-result/1");
  assert.equal(result.plan.decision, "requires_approval");
  assert.equal(result.receipt.execution_status, "dispatched");
  assert.deepEqual(result.result, { body: "Build passed." });
});

test("a changed destination or stale approval cannot call the host tool", async () => {
  let count = 0;
  const guarded = makeTool({ execute: async () => { count++; } });
  const changed = await guarded({ to: "other@example.test", body: "Build passed." });
  assert.equal(changed.receipt.reason, "no_exact_rule");
  assert.equal(changed.receipt.execution_status, "blocked");
  assert.equal(Object.hasOwn(changed, "result"), false);

  const stale = makeTool({
    requestApproval: async () => ({ approved: true, proposal_sha256: "0".repeat(64) }),
    execute: async () => { count++; }
  });
  assert.equal((await stale({ to: route, body: "Changed." })).receipt.reason,
    "approval_missing_or_mismatched");
  assert.equal(count, 0);
});

test("the callback receives frozen arguments after input mutation during approval", async () => {
  const input = { to: route, body: "Original" };
  let received;
  const guarded = makeTool({
    requestApproval: async ({ proposal, proposal_sha256 }) => {
      input.body = "Mutated";
      proposal.arguments.body = "Mutated";
      return { approved: true, proposal_sha256 };
    },
    execute: async args => { received = args; return "simulated"; }
  });
  const output = await guarded(input);
  assert.equal(output.receipt.execution_status, "dispatched");
  assert.deepEqual(received, { to: route, body: "Original" });
});

test("policy revocation blocks, a thrown callback is unknown, and no retry occurs", async () => {
  const hostPolicy = policy();
  let count = 0;
  const revoked = makeTool({
    policy: hostPolicy,
    requestApproval: async ({ proposal_sha256 }) => {
      hostPolicy.rules.length = 0;
      return { approved: true, proposal_sha256 };
    },
    execute: async () => { count++; }
  });
  assert.equal((await revoked({ to: route, body: "Hi" })).receipt.reason, "policy_changed");
  assert.equal(count, 0);

  const uncertain = makeTool({ execute: async () => { count++; throw new Error("Transport failed"); } });
  const output = await uncertain({ to: route, body: "Hi" });
  assert.equal(output.receipt.execution_status, "unknown");
  assert.equal(output.receipt.reason, "host_dispatch_error");
  assert.equal(count, 1);
});

test("invalid host mappings and malformed arguments fail without execution", async () => {
  let count = 0;
  const guarded = makeTool({ execute: async () => { count++; } });
  assert.equal((await guarded({ to: route, body: "Hi", bad: Infinity })).receipt.reason,
    "AML_CANONICAL_JSON_NON_FINITE_NUMBER");
  assert.equal(count, 0);
  const broken = makeTool({ resourceFor: () => { throw new Error("Host mapping failed"); },
    execute: async () => { count++; } });
  await assert.rejects(broken({ to: route }), /Host mapping failed/);
  assert.equal(count, 0);
});
