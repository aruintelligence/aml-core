import { createA2UIFunctionGate } from "./a2ui-function-gate.mjs";

// Local simulation only. A real renderer supplies the active catalog, session,
// schema validation, trusted approval, callback, and response transport.
const catalogId = "https://example.test/catalog/action.json";
const team = "team@example.test";
let callbackCount = 0;
const gate = createA2UIFunctionGate({
  catalogId, functionName: "sendMessage", allowedCallers: "agentOnly",
  validateArgs: args => Object.keys(args).sort().join(",") === "body,to" &&
    typeof args.to === "string" && typeof args.body === "string",
  tool: "send_message", effect: "send", purpose: "Send a status update",
  resourceFor: args => args.to,
  policy: { protocol: "aml-action-policy/1", rules: [
    { tool: "send_message", effect: "send", resource: team, requires_approval: true }
  ] },
  requestApproval: async ({ proposal_sha256 }) => ({ approved: true, proposal_sha256 }),
  execute: async args => { callbackCount++; return { simulated: true, recipient: args.to }; }
});
const message = to => ({ version: "v1.0", callRendererFunction: {
  functionCallId: `send_${to === team ? "team" : "outside"}`,
  callFunction: { call: "sendMessage", catalogId, args: { to, body: "Build passed." } }
} });

const exact = await gate(message(team));
const changed = await gate(message("outside@example.test"));
process.stdout.write(JSON.stringify({
  simulation: true, exact, changed, callback_count: callbackCount
}, null, 2) + "\n");
