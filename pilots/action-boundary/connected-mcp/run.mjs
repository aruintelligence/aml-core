#!/usr/bin/env node
// Execute the existing host gate against an SDK Client and a child MCP server.
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { Client } from "@modelcontextprotocol/client";
import { StdioClientTransport } from "@modelcontextprotocol/client/stdio";
import { createMCPCallToolGate } from "../mcp-call-tool-gate.mjs";
import { planAction } from "../boundary.mjs";

const serverKey = "local-notice-fixture";
const name = "send_notice";
const tool = `mcp:${serverKey}:${name}`;
const purpose = "Record a notice locally";
const team = "team@example.test";
const outside = "outside@example.test";
const policy = { protocol: "aml-action-policy/1", rules: [
  { tool, effect: "send", resource: team, requires_approval: true }
] };
const call = (to, body = "Build passed.") => ({ name, arguments: { to, body } });
const oldDigest = planAction({ protocol: "aml-proposed-action/1", tool,
  effect: "send", resource: team, purpose, arguments: call(team).arguments }, policy).proposal_sha256;

const scenarios = [
  { id: "outside", title: "Outside the exact rule", input: call(outside),
    expected: { calls: 0, reason: "no_exact_rule", status: "not_called" } },
  { id: "approved", title: "Matching route and approval", input: call(team),
    expected: { calls: 1, reason: "host_dispatch_returned", status: "returned" } },
  { id: "changed_body", title: "Approval bound to old bytes", input: call(team, "Changed body"), stale: true,
    expected: { calls: 0, reason: "approval_missing_or_mismatched", status: "not_called" } },
  { id: "extra_recipient", title: "Unexpected recipient field", input: {
    name, arguments: { to: team, body: "Build passed.", cc: [outside] } },
    expected: { calls: 0, rejection: "invalid_arguments", status: "not_called" } },
  { id: "wrong_tool", title: "Unregistered tool name", input: {
    name: "delete_records", arguments: { to: team, body: "Build passed." } },
    expected: { calls: 0, rejection: "invalid_or_unregistered_call", status: "not_called" } },
  { id: "tool_error", title: "Server handler returns an error", input: call(team, "Return an error"),
    expected: { calls: 1, reason: "host_dispatch_returned", status: "tool_error" } }
];

function readAudit(file) {
  return fs.readFileSync(file, "utf8").trim().split("\n").filter(Boolean).map(JSON.parse);
}

export async function runConnectedMCP() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "aml-mcp-stdio-"));
  const auditPath = path.join(dir, "server-handlers.jsonl");
  fs.writeFileSync(auditPath, "");
  const client = new Client({ name: "aml-host-pilot", version: "1.0.0" });
  try {
    const transport = new StdioClientTransport({ command: process.execPath,
      args: [fileURLToPath(new URL("./server.mjs", import.meta.url))],
      env: { PATH: process.env.PATH ?? "", AML_MCP_AUDIT_PATH: auditPath }, stderr: "pipe" });
    transport.stderr.on("data", chunk => process.stderr.write(chunk));
    await client.connect(transport); // SDK initialize handshake over child stdio.
    const listed = (await client.listTools()).tools.find(item => item.name === name);
    assert.ok(listed, "Fixture tool must be advertised by the connected server");
    assert.equal(listed.annotations?.readOnlyHint, true);
    assert.equal(client.getServerVersion()?.name, "local-notice-fixture");

    // Intentionally unsafe comparison: the advertised hint alone causes an
    // actual SDK tools/call to reach the local server handler.
    const unsafeInput = call(outside);
    const beforeCount = readAudit(auditPath).length;
    if (listed.annotations.readOnlyHint) await client.callTool(unsafeInput);
    const unsafeEntries = readAudit(auditPath).slice(beforeCount);
    assert.deepEqual(unsafeEntries, [{ tool: name, ...unsafeInput.arguments }]);

    const rows = [];
    for (const spec of scenarios) {
      const gate = createMCPCallToolGate({ client, serverKey, name, effect: "send", purpose,
        validateArgs: args => Object.keys(args).sort().join(",") === "body,to" &&
          typeof args.to === "string" && typeof args.body === "string",
        resourceFor: args => args.to, policy,
        requestApproval: async ({ proposal_sha256 }) => ({ approved: true,
          proposal_sha256: spec.stale ? oldDigest : proposal_sha256 })
      });
      const count = readAudit(auditPath).length;
      const result = await gate(structuredClone(spec.input));
      const reached = readAudit(auditPath).slice(count);
      assert.equal(reached.length, spec.expected.calls, spec.id);
      assert.equal(result.mcp_result_status, spec.expected.status, spec.id);
      if (spec.expected.rejection) assert.equal(result.rejection, spec.expected.rejection, spec.id);
      else assert.equal(result.receipt?.reason, spec.expected.reason, spec.id);
      if (reached.length) assert.deepEqual(reached[0], { tool: name, ...spec.input.arguments }, spec.id);
      rows.push({ id: spec.id, title: spec.title, proposed_call: spec.input,
        server_handler_calls: reached.length, server_audit: reached,
        verdict: { rejection: result.rejection, plan: result.plan, receipt: result.receipt,
          mcp_result_status: result.mcp_result_status,
          ...(result.result ? { result: result.result } : {}) } });
    }
    return { protocol: "aml-connected-mcp-pilot/1",
      provenance: "project-authored local MCP SDK v2 client/server over child-process stdio",
      sdk: "@modelcontextprotocol/client@2.3.1 + @modelcontextprotocol/server@2.3.1",
      server: "local-notice-fixture", transport: "stdio child process",
      advertised_read_only_hint: listed.annotations.readOnlyHint,
      unsafe_comparison: { proposed_call: unsafeInput,
        server_handler_calls: unsafeEntries.length, server_audit: unsafeEntries },
      cases: rows,
      limits: "The server only appends a temporary local audit line. This is a connected SDK pilot, not an external send, independent security assessment, general MCP interception, authenticated approval, or proof of provider delivery. A host must ensure every effectful call path uses its gate and bind the actual server/account and final provider request." };
  } finally {
    await client.close();
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

if (process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1])) {
  console.log(JSON.stringify(await runConnectedMCP(), null, 2));
}
