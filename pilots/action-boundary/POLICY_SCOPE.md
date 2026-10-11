# Policy scope: the same address can carry a different message

The action policy's exact rule matches `tool`, `effect`, and `resource`. It does not match `purpose` or `arguments`. The proposal SHA-256 digest covers the entire canonical proposal, but a digest difference by itself is not a denial. When a matching rule has `requires_approval: false`, the reference boundary may invoke the host callback for a changed body at the same destination.

This is an intentional distinction between a **rule's scope** and an **exact proposal approval**. It is easy to miss when reading “exact host rule,” so the [visual Policy X-ray](https://aruintelligence.github.io/aml-core/action-policy-scope.html?case=changed_body#cases) makes it testable.

## Reproduce the eight-case report

From a repository checkout:

```bash
node scripts/build-action-policy-scope-report.mjs --check
node --test test/action-boundary-policy-scope.test.js
```

Remove `--check` to regenerate `docs/action-policy-scope-report.json`. The builder calls the actual `planAction` and `dispatchAction` reference functions, counts simulated tool callbacks, asserts each expected outcome, and produces the report used by the browser page. The report is project-authored evidence for these fixtures; it never sends a message.

| Changed part | Rule with no approval | Rule requiring original digest |
|---|---|---|
| Original proposal | One simulated callback | One simulated callback |
| Message body, purpose, or extra argument | One simulated callback each | Zero; fixed original digest is stale |
| Destination, effect, or tool | Zero; no exact rule | Zero; no exact rule |
| Object key order only | One simulated callback | One simulated callback; same canonical digest |

The second column uses a deliberately fixed, host-supplied digest for the original proposal. It is **not** a person, an identity system, or a production approval flow. A real host may approve a changed proposal after reviewing it, and then that new digest can dispatch. If a host must reject certain content regardless of approval, it needs a separate content rule enforced before the callback.

## Host integration choice

The host must derive `resource` from the actual tool arguments and keep its policy and callbacks outside model control. For a send tool, an approval-required rule can make the host review the full frozen proposal:

```js
import { createGuardedToolExecute } from "./guarded-tool.mjs";

const execute = createGuardedToolExecute({
  tool: "send_message", effect: "send", purpose: "Send a team update",
  resourceFor: args => args.to,
  policy: { protocol: "aml-action-policy/1", rules: [
    { tool: "send_message", effect: "send",
      resource: "team@example.test", requires_approval: true }
  ] },
  requestApproval: async ({ proposal, proposal_sha256 }, context) =>
    hostAuthorizeExactProposal(proposal, proposal_sha256, context),
  execute: async (args, context) => hostSendMessage(args.to, args.body, context)
});
```

`hostAuthorizeExactProposal` and `hostSendMessage` are functions the integrator must implement. Approval must return `{ approved: true, proposal_sha256 }` for the exact digest after genuine host authorization. The included [function-tool quickstart](../../docs/AGENT_TOOL_QUICKSTART.md) explains replay claims, unknown outcomes, and host responsibilities. A permissive callback that echoes any supplied digest does not provide meaningful authorization.

MCP Apps also routes interactive View `tools/call` requests through the Host before they reach the MCP server, and its tool visibility metadata distinguishes model and app callers ([official overview](https://apps.extensions.modelcontextprotocol.io/api/documents/overview.html)). That architecture motivates a host decision at the tool boundary; this pilot does **not** implement or claim MCP Apps conformance.

## Limits

The fixture's host maps `arguments.to` and `resource` consistently. The reference boundary cannot determine whether a host lied about its tool, effect, destination, purpose, or what an external service ultimately did. An allow receipt records callback return, not delivery. The visual page reads a checked-in report; it does not execute user-supplied tools. This work does not measure harm, consent, user experience, or independent adoption.
