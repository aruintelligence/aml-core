import assert from "node:assert/strict";
import fs from "node:fs";
import { createA2UIFunctionGate } from "../pilots/action-boundary/a2ui-function-gate.mjs";
import { createLocalA2UIInvocationClaims } from "../pilots/action-boundary/a2ui-invocation-claims.mjs";

const outputPath = new URL("../docs/a2ui-function-report.json", import.meta.url);
const catalogId = "https://example.test/catalog/action.json";
const destination = "team@example.test";
const baseArgs = () => ({ to: destination, body: "Build passed." });
const policy = () => ({ protocol: "aml-action-policy/1", rules: [
  { tool: "send_message", effect: "send", resource: destination, requires_approval: true }
] });
const envelope = args => ({ version: "v1.0", callRendererFunction: {
  functionCallId: "send_1", callFunction: { call: "sendMessage", catalogId, args }
} });

async function runCase({ id, title, description, change, expected }) {
  let callbackCount = 0;
  const observedArguments = [];
  const config = {
    catalogId, functionName: "sendMessage", allowedCallers: "agentOnly",
    validateArgs: args => Object.keys(args).sort().join(",") === "body,to" &&
      typeof args.to === "string" && typeof args.body === "string",
    tool: "send_message", effect: "send", purpose: "Send a status update",
    resourceFor: args => args.to, policy: policy(),
    requestApproval: async ({ proposal_sha256 }) => ({ approved: true, proposal_sha256 }),
    claimInvocation: createLocalA2UIInvocationClaims({ sessionFor: context => context.sessionId }).claim,
    execute: async args => {
      callbackCount++;
      observedArguments.push(args);
      return { simulated: true, to: args.to };
    }
  };
  const message = envelope(baseArgs());
  change(config, message);
  const submittedRequest = structuredClone(message);
  const { response, aml, invocation } = await createA2UIFunctionGate(config)(message,
    { sessionId: "report-host-session" });
  const status = aml?.receipt.execution_status ?? "not_reached";
  const reason = aml?.receipt.reason ?? response.error?.code;
  assert.equal(status, expected.status, id);
  assert.equal(reason, expected.reason, id);
  assert.equal(callbackCount, expected.callbacks, id);
  assert.equal(response.error?.functionCallId ??
    response.rendererFunctionResponse?.functionCallId, "send_1", id);
  if (id === "mutated_during_approval") {
    assert.deepEqual(observedArguments, [baseArgs()], id);
  }
  return {
    id, title, description, request: submittedRequest,
    ...(JSON.stringify(message) !== JSON.stringify(submittedRequest) ? { request_after_approval: message } : {}),
    response, invocation: invocation ?? "not_reached",
    aml_plan: aml?.plan ?? null, aml_receipt: aml?.receipt ?? null,
    callback_count: callbackCount, observed_arguments: observedArguments
  };
}

const cases = [
  {
    id: "approved_exact", title: "Exact call + bound approval",
    description: "An agent-authorized catalog function matches the host's exact destination rule and digest-bound simulated approval.",
    change: () => {}, expected: { status: "dispatched", reason: "host_dispatch_returned", callbacks: 1 }
  },
  {
    id: "changed_destination", title: "Destination changed",
    description: "The catalog permits sendMessage, but the new recipient has no matching host policy rule.",
    change: (_, message) => { message.callRendererFunction.callFunction.args.to = "outside@example.test"; },
    expected: { status: "blocked", reason: "no_exact_rule", callbacks: 0 }
  },
  {
    id: "renderer_only", title: "Renderer-only function",
    description: "The active host catalog marks this entry rendererOnly, so A2UI rejects the agent call before AML.",
    change: config => { config.allowedCallers = "rendererOnly"; },
    expected: { status: "not_reached", reason: "INVALID_FUNCTION_CALL", callbacks: 0 }
  },
  {
    id: "wrong_catalog", title: "Unregistered catalog",
    description: "The agent names a different catalog ID; the host does not resolve it to this function.",
    change: (_, message) => { message.callRendererFunction.callFunction.catalogId = "https://outside.test/unknown.json"; },
    expected: { status: "not_reached", reason: "INVALID_FUNCTION_CALL", callbacks: 0 }
  },
  {
    id: "unknown_function", title: "Unregistered function",
    description: "The agent names a function absent from this registered host entry.",
    change: (_, message) => { message.callRendererFunction.callFunction.call = "deleteLocalFile"; },
    expected: { status: "not_reached", reason: "INVALID_FUNCTION_CALL", callbacks: 0 }
  },
  {
    id: "invalid_args", title: "Schema mismatch",
    description: "The trusted host argument validator rejects a non-string body before AML or the callback.",
    change: (_, message) => { message.callRendererFunction.callFunction.args.body = 42; },
    expected: { status: "not_reached", reason: "INVALID_FUNCTION_CALL", callbacks: 0 }
  },
  {
    id: "stale_approval", title: "Approval for other bytes",
    description: "The simulated approval returns the wrong proposal SHA-256 and cannot authorize dispatch.",
    change: config => { config.requestApproval = async () => ({
      approved: true, proposal_sha256: "0".repeat(64)
    }); }, expected: { status: "blocked", reason: "approval_missing_or_mismatched", callbacks: 0 }
  },
  {
    id: "mutated_during_approval", title: "Input mutated while waiting",
    description: "The caller changes the original argument object during approval; the callback receives the frozen approved proposal.",
    change: (config, message) => { config.requestApproval = async ({ proposal_sha256 }) => {
      message.callRendererFunction.callFunction.args.body = "Mutated after plan";
      return { approved: true, proposal_sha256 };
    }; }, expected: { status: "dispatched", reason: "host_dispatch_returned", callbacks: 1 }
  },
  {
    id: "uncertain_callback", title: "Uncertain callback",
    description: "A callback throws after invocation; the receipt stays unknown and the gate never retries.",
    change: config => { const original = config.execute;
      config.execute = async args => { await original(args); throw new Error("simulated transport failure"); };
    }, expected: { status: "unknown", reason: "host_dispatch_error", callbacks: 1 }
  }
];

const report = {
  protocol: "aml-a2ui-function-report/1",
  scope: "Project-authored local A2UI v1.0 callRendererFunction adapter simulation. No live message, person, renderer session, or external A2UI conformance claim.",
  source: "pilots/action-boundary/a2ui-function-gate.mjs",
  spec: "https://a2ui.org/specification/v1.0-a2ui/",
  cases: await Promise.all(cases.map(runCase))
};
const serialized = JSON.stringify(report, null, 2) + "\n";
if (process.argv.includes("--check")) {
  assert.equal(fs.readFileSync(outputPath, "utf8"), serialized,
    "A2UI visual report is stale; regenerate it with node scripts/build-a2ui-function-report.mjs");
  process.stdout.write(`A2UI report matches ${report.cases.length} live cases\n`);
} else {
  fs.writeFileSync(outputPath, serialized);
  process.stdout.write(`Wrote ${report.cases.length} A2UI cases to ${outputPath.pathname}\n`);
}
