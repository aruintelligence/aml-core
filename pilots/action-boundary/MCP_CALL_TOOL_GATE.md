# MCP `Client.callTool` → ĀML host action gate

[Open the eight-case visual lab](https://aruintelligence.github.io/aml-core/mcp-call-lab.html) · [Read the MCP 2026-07-28 tools specification](https://modelcontextprotocol.io/specification/2026-07-28/server/tools) · [See the SDK `callTool` shape](https://ts.sdk.modelcontextprotocol.io/v2/clients/calling)

MCP tools are selected by name and invoked with an `arguments` object. A server can advertise `readOnlyHint`, `destructiveHint`, and other annotations, but the MCP specification says clients must treat annotations as untrusted unless the server is trusted. Even a trusted annotation describes a tool; it does not authorize a particular recipient, body, or effect.

`createMCPCallToolGate` is a narrow **client-side** wrapper for one connected MCP client and one configured tool. The host assigns a stable `serverKey` to its actual client connection and configures the exact tool name, effect, purpose, argument validation, destination mapper, policy, and approval callback. The agent supplies only `{ name, arguments }`. The wrapper snapshots the JSON arguments, checks the host schema, builds a `mcp:<serverKey>:<name>` AML proposal, derives its resource from those arguments, then calls the connected client's `callTool({ name, arguments })` only after the AML action gate permits dispatch. It never uses tool-list annotations as policy.

```js
import { createMCPCallToolGate } from "./mcp-call-tool-gate.mjs";

const callNotice = createMCPCallToolGate({
  client: connectedHostOwnedMCPClient,
  serverKey: "orders-prod", // host-assigned identity, not serverInfo.name
  name: "send_notice",
  effect: "send",
  purpose: "Send a customer notice",
  validateArgs: args => Object.keys(args).sort().join(",") === "body,to" &&
    typeof args.to === "string" && typeof args.body === "string",
  resourceFor: args => args.to,
  policy: { protocol: "aml-action-policy/1", rules: [{
    tool: "mcp:orders-prod:send_notice", effect: "send",
    resource: "team@example.test", requires_approval: true
  }] },
  requestApproval: hostApprovalForExactProposalDigest
});

const verdict = await callNotice({
  name: "send_notice",
  arguments: { to: "team@example.test", body: "Build passed." }
}, trustedHostContext);
// Inspect verdict.plan, verdict.receipt, verdict.mcp_result_status.
```

Run the project-authored local cases from the repository root with Node 22:

```bash
node pilots/action-boundary/mcp-call-demo.mjs
node --test test/mcp-call-tool-gate.test.js
node scripts/build-mcp-call-report.mjs --check
```

The deliberately flawed comparison host treats an advertised `readOnlyHint: true` as permission and invokes an outside destination once. Under a rule permitting only `team@example.test`, the AML wrapper blocks the outside call before `callTool`. Seven other cases cover an approved destination, stale digest approval, unexpected recipient field, different tool name, `isError: true` result, a thrown transport, and an `input_required` result. The report records actual callbacks and receipts from an in-memory client with the same `callTool` method shape; it does **not** connect to an MCP server or use the SDK.

The receipt's `dispatched` status says the host callback returned. MCP `isError: true` is reported separately as `tool_error`. A thrown client call gets AML `unknown`, because the external effect may already have begun; do not retry automatically. `input_required` is also reported separately: this wrapper does not intercept SDK-managed input rounds or any hidden retry. Configure such rounds deliberately and reapply the host boundary to each new effectful invocation. Tool results are untrusted server content and need their own validation before being shown to a model.

**Integration responsibility.** Keep the connected client, `serverKey`, validator, mapper, policy, and approval outside model or server-advertised data. Bind the configured client to the intended server and account; the MCP server's advertised `serverInfo.name` is not a unique security identity. Map *every* destination the real tool can use, including provider-side request construction. Ensure every host call path uses the wrapper, provide real authenticated and one-use approval where appropriate, and reconcile uncertain outcomes. This small adapter accepts only `name` and `arguments`; it is not a full MCP client, protocol conformance suite, transport interceptor, output validator, prompt-injection defense, or proof of external delivery.
