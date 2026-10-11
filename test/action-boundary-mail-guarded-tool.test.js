import test from "node:test";
import assert from "node:assert/strict";
import { createGuardedToolExecute } from "../pilots/action-boundary/guarded-tool.mjs";
import { createMailGuardedToolExecute } from "../pilots/action-boundary/mail-guarded-tool.mjs";
import { mailTargetResource } from "../pilots/action-boundary/mail-target-manifest.mjs";

const base = () => ({ to: "team@example.test", subject: "Release", body: "Ready." });
const rule = (args, requires_approval = false) => ({ protocol: "aml-action-policy/1", rules: [
  { tool: "send_message", effect: "send", resource: mailTargetResource(args).resource, requires_approval }
] });

test("a To-only mapping reaches a BCC callback; complete mail mapping blocks it", async () => {
  const added = { ...base(), bcc: ["outside@example.test"] };
  let oldCalls = 0, newCalls = 0, oldArgs;
  const old = createGuardedToolExecute({ tool: "send_message", effect: "send",
    purpose: "Send release", resourceFor: args => args.to,
    policy: { protocol: "aml-action-policy/1", rules: [
      { tool: "send_message", effect: "send", resource: "team@example.test", requires_approval: false }
    ] }, execute: async args => { oldCalls++; oldArgs = args; return { simulated: true }; } });
  const current = createMailGuardedToolExecute({ purpose: "Send release", policy: rule(base()),
    execute: async () => { newCalls++; } });
  assert.equal((await old(added)).receipt.execution_status, "dispatched");
  const outcome = await current(added);
  assert.deepEqual(oldArgs.bcc, ["outside@example.test"]);
  assert.deepEqual([oldCalls, newCalls], [1, 0]);
  assert.deepEqual([outcome.receipt.execution_status, outcome.receipt.reason], ["blocked", "no_exact_rule"]);
});

test("aligned and intended multi-recipient calls return from one simulated callback", async () => {
  for (const args of [base(), { ...base(), cc: ["editor@example.test"], bcc: ["archive@example.test"] }]) {
    let calls = 0, received;
    const tool = createMailGuardedToolExecute({ purpose: "Send release", policy: rule(args),
      execute: async (frozen, context) => { calls++; received = { frozen, context }; return { simulated: true }; } });
    const context = { test: "fixture" };
    const outcome = await tool(args, context);
    assert.equal(outcome.receipt.execution_status, "dispatched");
    assert.equal(calls, 1);
    assert.deepEqual(received, { frozen: args, context });
  }
});

test("unknown delivery fields and malformed recipients stop before the callback", async () => {
  let calls = 0;
  const tool = createMailGuardedToolExecute({ purpose: "Send release", policy: rule(base()),
    execute: async () => { calls++; } });
  await assert.rejects(tool({ ...base(), recipients: ["outside@example.test"] }), /unsupported_mail_arguments/);
  await assert.rejects(tool({ ...base(), bcc: null }), /invalid_mail_recipients/);
  assert.equal(calls, 0);
});

test("approval is bound to the frozen proposal and stale approval blocks", async () => {
  const args = base();
  let calls = 0;
  const accepted = createMailGuardedToolExecute({ purpose: "Send release", policy: rule(args, true),
    requestApproval: async ({ proposal_sha256 }) => ({ approved: true, proposal_sha256 }),
    execute: async frozen => { calls++; assert.equal(frozen.body, "Ready."); } });
  const acceptedResult = await accepted(args);
  assert.equal(acceptedResult.receipt.execution_status, "dispatched");
  const stale = createMailGuardedToolExecute({ purpose: "Send release", policy: rule(args, true),
    requestApproval: async () => ({ approved: true, proposal_sha256: "0".repeat(64) }),
    execute: async () => { calls++; } });
  assert.equal((await stale(args)).receipt.reason, "approval_missing_or_mismatched");
  assert.equal(calls, 1);
});

test("a changed body remains inside recipient scope under an unreviewed rule", async () => {
  let calls = 0;
  const tool = createMailGuardedToolExecute({ purpose: "Send release", policy: rule(base()),
    execute: async frozen => { calls++; assert.equal(frozen.body, "Changed text."); } });
  assert.equal((await tool({ ...base(), body: "Changed text." })).receipt.execution_status, "dispatched");
  assert.equal(calls, 1);
});
