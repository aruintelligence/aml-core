#!/usr/bin/env node
// Measured in-memory MCP Client.callTool-shaped callback, not a connected server.
import assert from "node:assert/strict";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { createMCPCallToolGate } from "./mcp-call-tool-gate.mjs";
import { planAction } from "./boundary.mjs";

const serverKey = "host-orders";
const name = "send_notice";
const tool = `mcp:${serverKey}:${name}`;
const purpose = "Send a customer notice";
const team = "team@example.test";
const outside = "outside@example.test";
const policy = () => ({ protocol: "aml-action-policy/1", rules: [
  { tool, effect: "send", resource: team, requires_approval: true }
] });
const params = (to = team, body = "Build passed.") =>
  ({ name, arguments: { to, body } });
const originalDigest = planAction({ protocol: "aml-proposed-action/1", tool,
  effect: "send", resource: team, purpose, arguments: params().arguments }, policy()).proposal_sha256;
const cases = [
  { id: "forged_read_only", title: "A forged read-only hint", input: params(outside),
    expected: { calls: 0, reason: "no_exact_rule", decision: "deny" } },
  { id: "approved_destination", title: "An exact, approved destination", input: params(),
    expected: { calls: 1, reason: "host_dispatch_returned", decision: "requires_approval" } },
  { id: "stale_approval", title: "Approval for old content", input: params(team, "Changed body"),
    approval: "old", expected: { calls: 0, reason: "approval_missing_or_mismatched", decision: "requires_approval" } },
  { id: "extra_recipient", title: "An unvalidated extra recipient", input: { name,
    arguments: { to: team, body: "Build passed.", cc: [outside] } },
    expected: { calls: 0, rejection: "invalid_arguments" } },
  { id: "other_tool", title: "A different tool name", input: { name: "remove_records",
    arguments: { to: team, body: "Build passed." } },
    expected: { calls: 0, rejection: "invalid_or_unregistered_call" } },
  { id: "tool_error", title: "The tool reports an error", input: params(), result: "error",
    expected: { calls: 1, reason: "host_dispatch_returned", result: "tool_error" } },
  { id: "transport_unknown", title: "Transport fails after the call starts", input: params(), result: "throw",
    expected: { calls: 1, reason: "host_dispatch_error", result: "unknown" } },
  { id: "input_required", title: "The tool requests another input round", input: params(), result: "input",
    expected: { calls: 1, reason: "host_dispatch_returned", result: "input_required" } }
];

function mockClient(spec, calls) {
  return { async callTool(input) {
    calls.push(structuredClone(input));
    if (spec.result === "throw") throw Error("simulated transport loss");
    if (spec.result === "error") return { resultType: "complete", isError: true,
      content: [{ type: "text", text: "provider error" }] };
    if (spec.result === "input") return { resultType: "input_required",
      inputRequests: { missing: { method: "elicitation/create" } } };
    return { resultType: "complete", isError: false,
      content: [{ type: "text", text: "simulated" }] };
  } };
}

export async function runMCPCallCases() {
  const rows = [];
  for (const spec of cases) {
    // Deliberately unsafe comparison host: it interprets an untrusted
    // tools/list hint as permission to skip its own action decision.
    const listing = { name: spec.input.name, annotations: { readOnlyHint: true } };
    const beforeCalls = [];
    if (listing.annotations.readOnlyHint === true) {
      try { await mockClient(spec, beforeCalls).callTool(structuredClone(spec.input)); }
      catch { /* the callback may already have had an effect */ }
    }
    const afterCalls = [];
    const gate = createMCPCallToolGate({ client: mockClient(spec, afterCalls),
      serverKey, name, effect: "send", purpose,
      validateArgs: args => Object.keys(args).sort().join(",") === "body,to" &&
        typeof args.to === "string" && typeof args.body === "string",
      resourceFor: args => args.to, policy: policy(),
      requestApproval: async ({ proposal_sha256 }) => ({ approved: true,
        proposal_sha256: spec.approval === "old" ? originalDigest : proposal_sha256 })
    });
    const after = await gate(structuredClone(spec.input));
    assert.equal(beforeCalls.length, 1, spec.id);
    assert.equal(afterCalls.length, spec.expected.calls, spec.id);
    if (spec.expected.rejection) assert.equal(after.rejection, spec.expected.rejection, spec.id);
    else {
      assert.equal(after.plan.decision, spec.expected.decision ?? "requires_approval", spec.id);
      assert.equal(after.receipt.reason, spec.expected.reason, spec.id);
      if (spec.expected.result) assert.equal(after.mcp_result_status, spec.expected.result, spec.id);
    }
    rows.push({ id: spec.id, title: spec.title, model_proposed_call: spec.input,
      advertised_read_only_hint: listing.annotations.readOnlyHint,
      before: { tool_callbacks: beforeCalls.length, forwarded: beforeCalls[0] },
      after: { tool_callbacks: afterCalls.length, rejection: after.rejection,
        plan: after.plan, receipt: after.receipt, mcp_result_status: after.mcp_result_status,
        forwarded: afterCalls[0] ?? null } });
  }
  return { protocol: "aml-mcp-call-tool-demo/1",
    provenance: "project-authored in-memory MCP Client.callTool-shaped callback",
    contract: "MCP 2026-07-28 tools/call name and arguments; no connected server or SDK",
    cases: rows,
    limits: "No connected MCP server, transport, real approval, output validation, automatic SDK input-round interception, or proof of external effect. A host must bind the configured client to its actual server and validate the tool's final provider request." };
}

if (process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1])) {
  console.log(JSON.stringify(await runMCPCallCases(), null, 2));
}
