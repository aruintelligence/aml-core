import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import { createA2UIFunctionGate as currentGate } from "../pilots/action-boundary/a2ui-function-gate.mjs";
import { createLocalA2UIInvocationClaims } from "../pilots/action-boundary/a2ui-invocation-claims.mjs";
import { createA2UIFunctionGate as legacyGate } from "../test/fixtures/legacy-a2ui-function-gate.mjs";

const outputPath = new URL("../docs/a2ui-invocation-replay-report.json", import.meta.url);
const fixturePath = new URL("../test/fixtures/legacy-a2ui-function-gate.mjs", import.meta.url);
const priorMain = "b8a777a9c0a4fb27c69bbebb83b18fc4bba62d1d";
const priorBlob = "68fdbb0ac5cd7518e6c4974cae04f5417c8d3d6e";
const adaptedSource = fs.readFileSync(fixturePath, "utf8");
const oldImport = 'import { createGuardedToolExecute } from "./guarded-tool.mjs";';
const adaptedImport = 'import { createGuardedToolExecute } from "../../pilots/action-boundary/guarded-tool.mjs";';
assert.equal(adaptedSource.split(adaptedImport).length, 2, "fixture import adjustment changed");
const originalSource = adaptedSource.replace(adaptedImport, oldImport);
const blobBytes = Buffer.from(originalSource, "utf8");
const fixtureBlob = crypto.createHash("sha1").update(
  Buffer.concat([Buffer.from(`blob ${blobBytes.length}\0`), blobBytes])
).digest("hex");
assert.equal(fixtureBlob, priorBlob, "the legacy fixture must match the prior main Git blob after restoring its import path");

const catalogId = "https://example.test/catalog/action.json";
const recipient = "team@example.test";
const specs = [
  { id: "sequential", title: "Same ID, sequential replay",
    description: "The exact A2UI message arrives twice in one host session.",
    attempts: [{ id: "call_1", body: "Original", session: "host-A" },
      { id: "call_1", body: "Original", session: "host-A" }], before: 2, after: 1 },
  { id: "concurrent", title: "Same ID, simultaneous replay",
    description: "Two calls race on one ID while host approval is asynchronous.",
    concurrent: true, attempts: [{ id: "call_2", body: "Original", session: "host-A" },
      { id: "call_2", body: "Original", session: "host-A" }], before: 2, after: 1 },
  { id: "changed_payload", title: "Same ID, changed payload",
    description: "The second call retains the ID but changes the body.",
    attempts: [{ id: "call_3", body: "Original", session: "host-A" },
      { id: "call_3", body: "Changed", session: "host-A" }], before: 2, after: 1 },
  { id: "separate_sessions", title: "Same ID, distinct host sessions",
    description: "The host supplies two different session identities; each has its own ID namespace.",
    attempts: [{ id: "call_4", body: "Original", session: "host-A" },
      { id: "call_4", body: "Original", session: "host-B" }], before: 2, after: 2 },
  { id: "new_id", title: "New ID, new invocation",
    description: "An agent can request a new invocation ID; this guard does not prevent separately authorized new actions.",
    attempts: [{ id: "call_5", body: "Original", session: "host-A" },
      { id: "call_6", body: "Original", session: "host-A" }], before: 2, after: 2 },
  { id: "store_unavailable", title: "Claim store unavailable",
    description: "The corrected bridge fails closed if the host claim store cannot confirm an ID.",
    storeUnavailable: true, attempts: [{ id: "call_7", body: "Original", session: "host-A" }],
    before: 1, after: 0 }
];

async function run(spec, createGate, corrected) {
  let callbackCount = 0;
  const claims = createLocalA2UIInvocationClaims({ sessionFor: context => context.sessionId });
  const handle = createGate({
    catalogId, functionName: "sendMessage", allowedCallers: "agentOnly",
    validateArgs: args => Object.keys(args).sort().join(",") === "body,to" &&
      typeof args.to === "string" && typeof args.body === "string",
    tool: "send_message", effect: "send", purpose: "Send a status update",
    resourceFor: args => args.to,
    policy: { protocol: "aml-action-policy/1", rules: [
      { tool: "send_message", effect: "send", resource: recipient, requires_approval: true }
    ] },
    requestApproval: async ({ proposal_sha256 }) => ({ approved: true, proposal_sha256 }),
    claimInvocation: spec.storeUnavailable ? () => { throw new Error("simulated store failure"); } : claims.claim,
    execute: async args => { callbackCount++; return { simulated: true, body: args.body }; }
  });
  const attempt = async ({ id, body, session }) => {
    const output = await handle({ version: "v1.0", callRendererFunction: {
      functionCallId: id, callFunction: { call: "sendMessage", catalogId,
        args: { to: recipient, body } }
    } }, { sessionId: session });
    return {
      function_call_id: id, host_session: session, body,
      invocation: output.invocation ?? "not_checked",
      response: output.response, receipt: output.aml?.receipt ?? null
    };
  };
  const outputs = spec.concurrent ? await Promise.all(spec.attempts.map(attempt)) :
    await (async () => { const result = []; for (const input of spec.attempts) result.push(await attempt(input)); return result; })();
  assert.equal(callbackCount, corrected ? spec.after : spec.before, spec.id);
  if (corrected && spec.after === 1 && spec.attempts.length === 2) {
    assert.equal(outputs.filter(x => x.invocation === "claimed").length, 1, spec.id);
    assert.equal(outputs.filter(x => x.invocation === "reused").length, 1, spec.id);
    assert.equal(outputs.find(x => x.invocation === "reused").response.error.code,
      "INVALID_FUNCTION_CALL", spec.id);
  }
  if (corrected && spec.storeUnavailable) {
    assert.equal(outputs[0].invocation, "unavailable");
    assert.equal(outputs[0].response.error.code, "EXECUTION_FAILED");
  }
  return { callback_count: callbackCount, attempts: outputs };
}

const cases = [];
for (const spec of specs) {
  const { before, after, attempts, concurrent, storeUnavailable, ...labels } = spec;
  cases.push({ ...labels, mode: concurrent ? "concurrent" : "sequential",
    before: await run(spec, legacyGate, false),
    after: await run(spec, currentGate, true) });
}
const report = {
  protocol: "aml-a2ui-invocation-replay-report/1",
  scope: "Project-authored local simulation. The historical module is the prior main Git blob with only its import path adjusted. No real renderer, second OS process, human approval, or external message.",
  prior_main_commit: priorMain, prior_module_blob_sha1: priorBlob,
  current_module: "pilots/action-boundary/a2ui-function-gate.mjs",
  spec: "https://a2ui.org/specification/v1.0-a2ui/",
  cases
};
const serialized = JSON.stringify(report, null, 2) + "\n";
if (process.argv.includes("--check")) {
  assert.equal(fs.readFileSync(outputPath, "utf8"), serialized,
    "A2UI replay visual report is stale; regenerate it with node scripts/build-a2ui-invocation-replay-report.mjs");
  process.stdout.write(`A2UI invocation replay report matches ${cases.length} historical/current cases\n`);
} else {
  fs.writeFileSync(outputPath, serialized);
  process.stdout.write(`Wrote ${cases.length} A2UI replay cases to ${outputPath.pathname}\n`);
}
