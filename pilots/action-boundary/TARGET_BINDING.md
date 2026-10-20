# Target binding before a tool callback

[Open the seven-case visual lab](https://aruintelligence.github.io/aml-core/target-binding-lab.html?case=forged_recipient).

The reference action rule matches `tool`, `effect`, and the proposal's declared `resource`. It cannot infer the destination a tool will use from arbitrary arguments. In the local counterexample, the proposal declares `team@example.test` while `arguments.to` is `outside@example.test`. A rule with `requires_approval: false` matches, and the reference callback receives the outside recipient. No message is actually sent.

`dispatchTargetBoundAction` is an opt-in, host-owned adapter. It snapshots the proposal, asks a tool-specific `resolveTarget` callback to derive the actual destination from frozen arguments, and requires exact equality with `resource` before approval or dispatch. A missing callback, missing target, resolver error, or mismatch blocks. When it matches, the existing action boundary handles policy, digest-bound approval, final recheck, frozen dispatch, and uncertain callback outcomes.

If the initial snapshot fails, the adapter returns a blocked receipt with `policy_decision: "deny"` and `proposal_sha256: null`. It does not retry the caller's object to manufacture a digest: a stateful getter might return different content on a second read. The regression test verifies one read and zero resolver, approval, and tool calls on that path.

```js
import { dispatchTargetBoundAction } from "./target-boundary.mjs";

const result = await dispatchTargetBoundAction(proposal, {
  policy: hostPolicy,
  resolveTarget({ tool, effect, arguments: args }) {
    if (tool !== "send_message" || effect !== "send") throw Error("unsupported_tool");
    if (typeof args.to !== "string" || !args.to.trim()) return null;
    return args.to;
  },
  requestApproval: hostApproval, // if the matching rule requires it
  consumeApproval: hostClaim,    // if a one-use host grant is used
  executeTool: async frozen => {
    // The real tool must use the same destination and schema as resolveTarget.
    return hostMailer.send({ to: frozen.arguments.to, body: frozen.arguments.body });
  }
});
```

The resolver must be written and controlled by the host, not the agent. It must cover every supported tool and destination shape: aliases, CC/BCC or multiple recipients, URLs, redirects, normalized addresses, and any field the downstream tool can use to change its destination. For multiple destinations, design a host-specific resource representation and compare the whole set. The [mail recipient manifest example](MAIL_TARGET_MANIFEST.md) reproduces a BCC bypass in the to-only mapper above, then binds To, CC, and BCC under one exact resource. If the tool rewrites or redirects after mapping, this local equality check is insufficient. Never allow a second unwrapped path to the same sensitive callback.

This adapter does not validate message content, authenticate a person, confer tool permission, or prove delivery. A changed body with the same correctly mapped recipient still passes an unreviewed rule. A digest-matching response in the report is a project-authored fixture, not a human approval. An `unknown` callback result still requires host reconciliation rather than an automatic retry. The wrapper is a JavaScript integration example, not an independent implementation or a new MCP/A2UI specification.

Reproduce the evidence:

```sh
node test/action-boundary-target-binding.test.js
node scripts/build-target-binding-report.mjs --check
```

The report generator runs both dispatch paths, asserts callback counts and receipt reasons, and checks the published JSON bytes. It uses in-memory simulated callbacks only. For adjacent implementation guidance, [OWASP's Excessive Agency guidance](https://genai.owasp.org/llmrisk/llm062025-excessive-agency/) recommends enforcing authorization in downstream systems, and [MCP Apps authorization](https://apps.extensions.modelcontextprotocol.io/api/documents/authorization.html) describes separate OAuth controls for protected tools. Neither source evaluates or endorses this project pilot.
