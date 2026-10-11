import test from "node:test";
import assert from "node:assert/strict";
import { createA2UIFunctionGate } from "../pilots/action-boundary/a2ui-function-gate.mjs";

const catalogId = "https://example.test/catalog/action.json";
const destination = "team@example.test";
const policy = () => ({ protocol: "aml-action-policy/1", rules: [
  { tool: "send_message", effect: "send", resource: destination, requires_approval: true }
] });
const call = (args = { to: destination, body: "Build passed." }, overrides = {}) => ({
  version: "v1.0", callRendererFunction: {
    functionCallId: "send_1",
    callFunction: { call: "sendMessage", catalogId, args, ...overrides }
  }
});
const makeGate = (overrides = {}) => createA2UIFunctionGate({
  catalogId, functionName: "sendMessage", allowedCallers: "agentOnly",
  validateArgs: args => Object.keys(args).sort().join(",") === "body,to" &&
    typeof args.to === "string" && typeof args.body === "string",
  tool: "send_message", effect: "send", purpose: "Send a status update",
  resourceFor: args => args.to, policy: policy(),
  requestApproval: async ({ proposal_sha256 }) => ({ approved: true, proposal_sha256 }),
  execute: async args => ({ to: args.to, body: args.body }), ...overrides
});

test("an A2UI v1.0 agent call receives a correlated result only after exact approval", async () => {
  const seen = [];
  const context = { session: "host-owned" };
  const gate = makeGate({ execute: async (args, ctx, frozen) => {
    seen.push({ args, ctx, frozen });
    return { local_simulation: true };
  } });
  const output = await gate(call(), context);
  assert.deepEqual(output.response, { version: "v1.0", rendererFunctionResponse: {
    functionCallId: "send_1", value: { local_simulation: true }
  } });
  assert.equal(output.aml.plan.decision, "requires_approval");
  assert.equal(output.aml.receipt.execution_status, "dispatched");
  assert.equal(output.aml.plan.proposal_sha256, output.aml.receipt.proposal_sha256);
  assert.equal(seen.length, 1);
  assert.equal(seen[0].ctx, context);
  assert.equal(seen[0].frozen.resource, destination);
});

test("catalog, function, caller, and schema rejections never reach AML or the callback", async () => {
  let count = 0;
  const execute = async () => { count++; };
  for (const envelope of [
    call(undefined, { call: "deleteLocalFile" }),
    call(undefined, { catalogId: "https://outside.test/catalog.json" }),
    call({ to: destination, body: 4 }),
    { ...call(), version: "v0.9" }
  ]) {
    const output = await makeGate({ execute })(envelope);
    assert.equal(output.response.error.code, "INVALID_FUNCTION_CALL");
    assert.equal(output.response.error.functionCallId, "send_1");
    assert.equal(output.aml, null);
  }
  const localOnly = await makeGate({ allowedCallers: "rendererOnly", execute })(call());
  assert.equal(localOnly.response.error.code, "INVALID_FUNCTION_CALL");
  assert.equal(localOnly.aml, null);
  assert.equal(count, 0);
  await assert.rejects(makeGate({ execute })({ version: "v1.0", callRendererFunction: {} }),
    /functionCallId/);
  assert.equal(count, 0);
});

test("resource substitution and a stale approval block after catalog authorization", async () => {
  let count = 0;
  const execute = async () => { count++; };
  const changed = await makeGate({ execute })(call({ to: "outside@example.test", body: "Build passed." }));
  assert.equal(changed.response.rendererFunctionResponse.error.code, "ACTION_BLOCKED");
  assert.equal(changed.aml.receipt.reason, "no_exact_rule");
  const stale = await makeGate({ execute,
    requestApproval: async () => ({ approved: true, proposal_sha256: "0".repeat(64) })
  })(call());
  assert.equal(stale.response.rendererFunctionResponse.error.code, "ACTION_BLOCKED");
  assert.equal(stale.aml.receipt.reason, "approval_missing_or_mismatched");
  assert.equal(count, 0);
});

test("approval-time mutation cannot change dispatched arguments; policy revocation blocks", async () => {
  const envelope = call();
  const seen = [];
  const output = await makeGate({
    requestApproval: async ({ proposal, proposal_sha256 }) => {
      envelope.callRendererFunction.callFunction.args.body = "Mutated";
      proposal.arguments.body = "Also mutated";
      return { approved: true, proposal_sha256 };
    },
    execute: async args => { seen.push(args); return null; }
  })(envelope);
  assert.equal(output.aml.receipt.execution_status, "dispatched");
  assert.deepEqual(seen, [{ to: destination, body: "Build passed." }]);
  assert.equal(output.response.rendererFunctionResponse.value, null);

  const livePolicy = policy();
  const revoked = await makeGate({ policy: livePolicy,
    requestApproval: async ({ proposal_sha256 }) => {
      livePolicy.rules.length = 0;
      return { approved: true, proposal_sha256 };
    }, execute: async () => { seen.push("unexpected"); }
  })(call());
  assert.equal(revoked.aml.receipt.reason, "policy_changed");
  assert.equal(seen.length, 1);
});

test("a thrown callback is uncertain and an unserializable response does not cause a retry", async () => {
  let count = 0;
  const uncertain = await makeGate({ execute: async () => {
    count++; throw new Error("transport might have sent");
  } })(call());
  assert.equal(uncertain.aml.receipt.execution_status, "unknown");
  assert.equal(uncertain.response.rendererFunctionResponse.error.code, "EXECUTION_FAILED");
  assert.equal(count, 1);

  const nonJSON = await makeGate({ execute: async () => { count++; return { id: 7n }; } })(call());
  assert.equal(nonJSON.aml.receipt.execution_status, "dispatched");
  assert.equal(nonJSON.response.rendererFunctionResponse.error.code, "EXECUTION_FAILED");
  assert.equal(Object.hasOwn(nonJSON.aml, "result"), false);
  assert.equal(count, 2);
});

test("host mapping failure still returns a correlated error without invoking the tool", async () => {
  let count = 0;
  const output = await makeGate({
    resourceFor: () => { throw new Error("host mapping failed"); },
    execute: async () => { count++; }
  })(call());
  assert.equal(output.response.rendererFunctionResponse.functionCallId, "send_1");
  assert.equal(output.response.rendererFunctionResponse.error.code, "EXECUTION_FAILED");
  assert.equal(output.aml, null);
  assert.equal(count, 0);
});
