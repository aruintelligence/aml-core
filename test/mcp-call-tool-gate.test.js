import test from "node:test";
import assert from "node:assert/strict";
import { createMCPCallToolGate, createOneUseMCPCallToolGate,
  createConnectionBoundMCPCallToolGate, mcpConnectionResource } from "../pilots/action-boundary/mcp-call-tool-gate.mjs";
import { runMCPCallCases } from "../pilots/action-boundary/mcp-call-demo.mjs";

const serverKey = "trusted-orders";
const name = "send_notice";
const team = "team@example.test";
const policy = () => ({ protocol: "aml-action-policy/1", rules: [
  { tool: `mcp:${serverKey}:${name}`, effect: "send", resource: team,
    requires_approval: true }
] });
const make = (client, overrides = {}) => createMCPCallToolGate({
  client, serverKey, name, effect: "send", purpose: "Send a notice",
  validateArgs: args => Object.keys(args).sort().join(",") === "body,to" &&
    typeof args.to === "string" && typeof args.body === "string",
  resourceFor: args => args.to, policy: policy(),
  requestApproval: async ({ proposal_sha256 }) => ({ approved: true, proposal_sha256 }),
  ...overrides
});
const input = (to = team, body = "Original") => ({ name, arguments: { to, body } });

test("strict MCP profile requires a consumer and rejects a reused approval", async () => {
  const client = { calls: 0, async callTool() { this.calls++; return { content: [] }; } };
  assert.throws(() => createOneUseMCPCallToolGate({}), /consumeApproval/);
  let consumed = false;
  const gate = createOneUseMCPCallToolGate({
    client, serverKey, name, effect: "send", purpose: "Send a notice",
    validateArgs: args => Object.keys(args).sort().join(",") === "body,to",
    resourceFor: args => args.to, policy: policy(),
    requestApproval: async ({ proposal_sha256 }) => ({ approved: true, proposal_sha256, approval_id: "fixture" }),
    consumeApproval: async () => {
      if (consumed) return false;
      consumed = true;
      return true;
    }
  });
  assert.equal((await gate(input())).receipt.execution_status, "dispatched");
  assert.equal((await gate(input())).receipt.reason, "approval_reused_or_expired");
  assert.equal(client.calls, 1);
});

test("connection-bound MCP approval cannot move to another host account", async () => {
  const reached = [];
  let account = "account-A";
  const client = { callTool: async call => { reached.push({ account, call }); return { content: [] }; } };
  const boundPolicy = { protocol: "aml-action-policy/1", rules: [{
    tool: `mcp:${serverKey}:${name}`, effect: "send",
    resource: mcpConnectionResource("account-A", team), requires_approval: true
  }] };
  let consumed = 0;
  const gate = createConnectionBoundMCPCallToolGate({
    client, serverKey, name, effect: "send", purpose: "Send a notice",
    connectionIdentity: "account-A", readConnectionIdentity: () => account,
    validateArgs: args => Object.keys(args).sort().join(",") === "body,to",
    resourceFor: args => args.to, policy: boundPolicy,
    requestApproval: async ({ proposal_sha256 }) => {
      account = "account-B";
      return { approved: true, proposal_sha256 };
    },
    consumeApproval: async () => { consumed++; return true; }
  });
  const outcome = await gate(input());
  assert.equal(outcome.plan.decision, "requires_approval");
  assert.equal(outcome.receipt.execution_status, "blocked");
  assert.equal(outcome.receipt.reason, "connection_changed");
  assert.equal(outcome.mcp_result_status, "not_called");
  assert.equal(consumed, 1);
  assert.deepEqual(reached, []);
  account = "account-A";
  const good = await createConnectionBoundMCPCallToolGate({
    client, serverKey, name, effect: "send", purpose: "Send a notice",
    connectionIdentity: "account-A", readConnectionIdentity: () => account,
    validateArgs: args => Object.keys(args).sort().join(",") === "body,to",
    resourceFor: args => args.to, policy: boundPolicy,
    requestApproval: async ({ proposal_sha256 }) => ({ approved: true, proposal_sha256 }),
    consumeApproval: async () => true
  })(input());
  assert.equal(good.receipt.execution_status, "dispatched");
  assert.deepEqual(reached, [{ account: "account-A", call: input() }]);
});

test("the measured hint counterexample blocks outside call and retains error semantics", async () => {
  const report = await runMCPCallCases();
  assert.equal(report.cases.length, 9);
  const forged = report.cases[0];
  assert.equal(forged.advertised_read_only_hint, true);
  assert.equal(forged.before.tool_callbacks, 1);
  assert.equal(forged.after.tool_callbacks, 0);
  assert.equal(forged.after.receipt.reason, "no_exact_rule");
  assert.equal(report.cases.find(x => x.id === "tool_error").after.mcp_result_status, "tool_error");
  assert.equal(report.cases.find(x => x.id === "transport_unknown").after.receipt.execution_status, "unknown");
  assert.equal(report.cases.find(x => x.id === "input_required").after.mcp_result_status, "input_required");
  const unreadable = report.cases.find(x => x.id === "unreadable_result");
  assert.equal(unreadable.after.tool_callbacks, 1);
  assert.equal(unreadable.after.receipt.execution_status, "dispatched");
  assert.equal(unreadable.after.mcp_result_status, "invalid_result");
});

test("the client receives frozen validated arguments after an awaited approval", async () => {
  const proposed = input();
  const forwarded = [];
  const gate = make({ callTool: async call => { forwarded.push(call); return { content: [] }; } }, {
    requestApproval: async ({ proposal_sha256 }) => {
      proposed.arguments.to = "outside@example.test";
      proposed.arguments.body = "Changed during approval";
      return { approved: true, proposal_sha256 };
    }
  });
  const result = await gate(proposed);
  assert.equal(result.receipt.execution_status, "dispatched");
  assert.deepEqual(forwarded, [input()]);
});

test("host server identity, exact tool name, and schema are checked before callTool", async () => {
  let calls = 0;
  const client = { callTool: async () => { calls++; return { content: [] }; } };
  const otherServer = await make(client, { serverKey: "other-server" })(input());
  assert.equal(otherServer.receipt.reason, "no_exact_rule");
  const gate = make(client);
  assert.equal((await gate({ ...input(), annotations: { readOnlyHint: true } })).rejection,
    "invalid_or_unregistered_call");
  assert.equal((await gate({ ...input(), name: "delete_all" })).rejection,
    "invalid_or_unregistered_call");
  assert.equal((await gate({ name, arguments: { ...input().arguments,
    bcc: ["outside@example.test"] } })).rejection, "invalid_arguments");
  assert.equal(calls, 0);
});

test("oversized sparse MCP arguments reject before index traversal", async () => {
  let calls = 0;
  let indexChecks = 0;
  const sparse = [];
  sparse.length = 0xffff_ffff;
  const inputArray = new Proxy(sparse, { has(target, key) {
    indexChecks++;
    return Reflect.has(target, key);
  } });
  const gate = make({ callTool: async () => { calls++; return { content: [] }; } });
  const outcome = await gate({ name, arguments: { to: team, body: "Original", sparse: inputArray } });
  assert.equal(outcome.rejection, "invalid_arguments");
  assert.equal(calls, 0);
  assert.equal(indexChecks, 0);
});

test("host mapping errors and approval failure reach zero callbacks", async () => {
  let calls = 0;
  const client = { callTool: async () => { calls++; return { content: [] }; } };
  const mapping = await make(client, { resourceFor: () => { throw Error("bad mapping"); } })(input());
  assert.equal(mapping.rejection, "host_mapping_or_policy_error");
  const approval = await make(client, { requestApproval: async () => ({ approved: false }) })(input());
  assert.equal(approval.receipt.reason, "approval_missing_or_mismatched");
  assert.equal(calls, 0);
});

test("an MCP error cannot be disguised as an input-required round", async () => {
  const gate = make({ callTool: async () => ({ isError: true,
    resultType: "input_required", content: [{ type: "text", text: "failed" }] }) });
  const outcome = await gate(input());
  assert.equal(outcome.receipt.execution_status, "dispatched");
  assert.equal(outcome.mcp_result_status, "tool_error");
});

test("an unreadable returned result preserves the dispatched receipt", async () => {
  let calls = 0;
  const gate = make({ callTool: async () => {
    calls++;
    return { get isError() { throw Error("unreadable result"); } };
  } });
  const outcome = await gate(input());
  assert.equal(calls, 1);
  assert.equal(outcome.receipt.execution_status, "dispatched");
  assert.equal(outcome.receipt.reason, "host_dispatch_returned");
  assert.equal(outcome.mcp_result_status, "invalid_result");
  assert.equal(Object.hasOwn(outcome, "result"), false);
});

test("a throwing resultType getter also preserves the dispatched receipt", async () => {
  let calls = 0;
  const gate = make({ callTool: async () => {
    calls++;
    return { isError: false, get resultType() { throw Error("unreadable resultType"); } };
  } });
  const outcome = await gate(input());
  assert.equal(calls, 1);
  assert.equal(outcome.receipt.execution_status, "dispatched");
  assert.equal(outcome.mcp_result_status, "invalid_result");
  assert.equal(Object.hasOwn(outcome, "result"), false);
});
