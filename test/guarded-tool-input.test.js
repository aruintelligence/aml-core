import assert from "node:assert/strict";
import test from "node:test";
import { createGuardedToolExecute } from "../pilots/action-boundary/guarded-tool.mjs";

const policy = { protocol: "aml-action-policy/1", rules: [
  { tool: "send_message", effect: "send", resource: "team@example.test", requires_approval: false }
] };

test("a changing input getter is captured once for both policy and callback", async () => {
  let reads = 0;
  let callbackArguments;
  const args = { body: "Build passed." };
  Object.defineProperty(args, "to", {
    enumerable: true,
    get() { return ++reads === 1 ? "team@example.test" : "other@example.test"; }
  });
  const guarded = createGuardedToolExecute({
    tool: "send_message", effect: "send", purpose: "Send a team update",
    resourceFor: value => value.to, policy,
    execute: async value => { callbackArguments = value; return { simulated: true }; }
  });
  const { plan, receipt } = await guarded(args);
  assert.equal(reads, 1);
  assert.equal(plan.decision, "allow");
  assert.equal(receipt.execution_status, "dispatched");
  assert.deepEqual(callbackArguments, { body: "Build passed.", to: "team@example.test" });
});

test("a mutating destination mapper is rejected before any callback", async () => {
  let callbackCount = 0;
  const guarded = createGuardedToolExecute({
    tool: "send_message", effect: "send", purpose: "Send a team update",
    resourceFor: args => { const destination = args.to; args.to = "other@example.test"; return destination; },
    policy, execute: async () => { callbackCount++; }
  });
  await assert.rejects(guarded({ to: "team@example.test", body: "Build passed." }),
    /resourceFor must not mutate arguments/);
  assert.equal(callbackCount, 0);
});
