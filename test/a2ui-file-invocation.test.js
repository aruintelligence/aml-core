import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { createFileA2UIInvocationClaims } from "../pilots/action-boundary/file-a2ui-invocation-claims.mjs";
import { runA2UIFileClaimRace } from "../pilots/action-boundary/a2ui-file-claim-race.mjs";
import { createA2UIFunctionGate } from "../pilots/action-boundary/a2ui-function-gate.mjs";

function temp() { return fs.mkdtempSync(path.join(os.tmpdir(), "aml-a2ui-file-test-")); }
const sessionFor = context => context.session;

test("a file claim is unique across store instances and scoped to a trusted session", () => {
  const directory = temp();
  try {
    const a = createFileA2UIInvocationClaims({ directory, sessionFor });
    const b = createFileA2UIInvocationClaims({ directory, sessionFor });
    assert.equal(a.claim({ functionCallId: "call-1" }, { session: "A" }), true);
    assert.equal(b.claim({ functionCallId: "call-1" }, { session: "A" }), false);
    assert.equal(b.claim({ functionCallId: "call-1" }, { session: "B" }), true);
    assert.equal(fs.readdirSync(directory).length, 2);
    assert.throws(() => b.claim({ functionCallId: " " }, { session: "A" }), /required/);
    assert.throws(() => b.claim({ functionCallId: "call-2" }, { session: "" }), /required/);
  } finally { fs.rmSync(directory, { recursive: true, force: true }); }
});

test("an untrusted, lost, or replaced claim directory fails closed", () => {
  const directory = temp();
  const replacement = `${directory}-old`;
  const link = `${directory}-link`;
  try {
    fs.chmodSync(directory, 0o777);
    assert.throws(() => createFileA2UIInvocationClaims({ directory, sessionFor }), /private/);
    fs.chmodSync(directory, 0o700);
    fs.symlinkSync(directory, link);
    assert.throws(() => createFileA2UIInvocationClaims({ directory: link, sessionFor }), /private/);
    const claims = createFileA2UIInvocationClaims({ directory, sessionFor });
    assert.equal(claims.claim({ functionCallId: "spent" }, { session: "A" }), true);
    fs.renameSync(directory, replacement);
    assert.throws(() => claims.claim({ functionCallId: "next" }, { session: "A" }), /ENOENT/);
    fs.mkdirSync(directory, { mode: 0o700 });
    assert.throws(() => claims.claim({ functionCallId: "next" }, { session: "A" }), /replaced/);
  } finally {
    fs.rmSync(link, { force: true });
    fs.rmSync(directory, { recursive: true, force: true });
    fs.rmSync(replacement, { recursive: true, force: true });
  }
});

test("a lost store returns a correlated gate failure with zero callbacks", async () => {
  const directory = temp();
  try {
    const claims = createFileA2UIInvocationClaims({ directory, sessionFor });
    const catalogId = "https://example.test/catalog/action.json";
    let calls = 0;
    const gate = createA2UIFunctionGate({ catalogId, functionName: "sendMessage",
      allowedCallers: "agentOnly", validateArgs: () => true, tool: "send_message",
      effect: "send", purpose: "Test", resourceFor: args => args.to,
      policy: { protocol: "aml-action-policy/1", rules: [{ tool: "send_message",
        effect: "send", resource: "team@example.test", requires_approval: false }] },
      claimInvocation: claims.claim, execute: async () => { calls++; }
    });
    fs.rmSync(directory, { recursive: true, force: true });
    const output = await gate({ version: "v1.0", callRendererFunction: {
      functionCallId: "call-1", callFunction: { call: "sendMessage", catalogId,
        args: { to: "team@example.test" } }
    } }, { session: "A" });
    assert.equal(output.invocation, "unavailable");
    assert.equal(output.response.error.code, "EXECUTION_FAILED");
    assert.equal(calls, 0);
  } finally { fs.rmSync(directory, { recursive: true, force: true }); }
});

test("two real processes expose and close the replay gap, including a new worker", async () => {
  const report = await runA2UIFileClaimRace();
  assert.deepEqual(report.cases.map(row => [row.id, row.before.tool_callbacks,
    row.after.tool_callbacks, row.after.claim_markers]), [
    ["two_workers", 2, 1, 1], ["changed_body", 2, 1, 1],
    ["after_restart", 2, 1, 1], ["separate_sessions", 2, 2, 2]
  ]);
});
