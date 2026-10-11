import test from "node:test";
import assert from "node:assert/strict";
import { dispatchTargetBoundAction } from "../pilots/action-boundary/target-boundary.mjs";
import { mailTargetResource, resolveMailTarget } from "../pilots/action-boundary/mail-target-manifest.mjs";

const approvedArgs = () => ({ to: "team@example.test", subject: "Release", body: "Ready." });
const proposal = (args, resource) => ({ protocol: "aml-proposed-action/1", tool: "send_message",
  effect: "send", resource, purpose: "Send a release update", arguments: args });
const policy = resource => ({ protocol: "aml-action-policy/1", rules: [
  { tool: "send_message", effect: "send", resource, requires_approval: false }
] });

test("a to-only mapper overlooks a BCC destination in the frozen callback", async () => {
  const args = { ...approvedArgs(), bcc: ["outside@example.test"] };
  let callbacks = 0, seen;
  const result = await dispatchTargetBoundAction(proposal(args, "team@example.test"), {
    policy: policy("team@example.test"), resolveTarget: ({ arguments: value }) => value.to,
    executeTool: async frozen => { callbacks++; seen = frozen.arguments.bcc; }
  });
  assert.equal(result.receipt.execution_status, "dispatched");
  assert.equal(callbacks, 1);
  assert.deepEqual(seen, ["outside@example.test"]);
});

test("the complete manifest blocks an added BCC or CC before a callback", async () => {
  const approved = mailTargetResource(approvedArgs());
  for (const field of ["bcc", "cc"]) {
    let callbacks = 0;
    const args = { ...approvedArgs(), [field]: ["outside@example.test"] };
    const result = await dispatchTargetBoundAction(proposal(args, approved.resource), {
      policy: policy(approved.resource), resolveTarget: resolveMailTarget,
      executeTool: async () => { callbacks++; }
    });
    assert.deepEqual([result.receipt.execution_status, result.receipt.reason],
      ["blocked", "target_mismatch"]);
    assert.equal(callbacks, 0);
    assert.notEqual(mailTargetResource(args).resource, approved.resource);
  }
});

test("aligned and explicitly authorized multiple recipients reach the simulated callback", async () => {
  for (const args of [approvedArgs(), { ...approvedArgs(), cc: ["editor@example.test"], bcc: ["archive@example.test"] }]) {
    const expected = mailTargetResource(args);
    let callbacks = 0, seen;
    const result = await dispatchTargetBoundAction(proposal(args, expected.resource), {
      policy: policy(expected.resource), resolveTarget: resolveMailTarget,
      executeTool: async frozen => { callbacks++; seen = mailTargetResource(frozen.arguments).manifest; }
    });
    assert.equal(result.receipt.execution_status, "dispatched");
    assert.equal(callbacks, 1);
    assert.deepEqual(seen, expected.manifest);
  }
});

test("unknown delivery fields and malformed recipient shapes fail closed", async () => {
  const approved = mailTargetResource(approvedArgs());
  const invalid = [
    { ...approvedArgs(), recipients: ["outside@example.test"] },
    { ...approvedArgs(), bcc: null },
    { ...approvedArgs(), cc: [""] },
    { ...approvedArgs(), to: " team@example.test" }
  ];
  for (const args of invalid) {
    assert.throws(() => mailTargetResource(args));
    let callbacks = 0;
    const result = await dispatchTargetBoundAction(proposal(args, approved.resource), {
      policy: policy(approved.resource), resolveTarget: resolveMailTarget,
      executeTool: async () => { callbacks++; }
    });
    assert.equal(result.receipt.reason, "target_resolution_error");
    assert.equal(callbacks, 0);
  }
});

test("recipient resource ignores content and still needs a separate content decision", async () => {
  const original = approvedArgs(), changed = { ...original, body: "Different text." };
  const target = mailTargetResource(original);
  assert.equal(mailTargetResource(changed).resource, target.resource);
  let callbacks = 0;
  const result = await dispatchTargetBoundAction(proposal(changed, target.resource), {
    policy: policy(target.resource), resolveTarget: resolveMailTarget,
    executeTool: async () => { callbacks++; }
  });
  assert.equal(result.receipt.execution_status, "dispatched");
  assert.equal(callbacks, 1);
});
