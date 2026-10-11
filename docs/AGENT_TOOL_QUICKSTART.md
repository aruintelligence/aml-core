# Put an ĀML boundary around one agent function tool

This experimental adapter wraps a host-owned `execute` callback. It produces a proposed-action plan and dispatch receipt for one function-tool call. The host supplies the actual policy, destination mapping, approval callback, and tool implementation.

## Run a 30-second local rehearsal

From this repository:

```bash
node pilots/action-boundary/guarded-tool-demo.mjs
```

The first fixture has an exact policy rule and a **simulated** approval; its callback returns a `would_send_to` object. The second changes the destination and is blocked before the callback. There is no network request, message delivery, or human authentication.

## Wrap your own function tool

This is the host-side shape. The host must implement `showAndAuthorizeExactProposal` and `sendThroughMyService` with its own authentication and authorization. Do not use the demo's automatic approval in a real integration.

```js
import { createGuardedToolExecute } from "./pilots/action-boundary/guarded-tool.mjs";

const policy = {
  protocol: "aml-action-policy/1",
  rules: [{
    tool: "send_message", effect: "send",
    resource: "team@example.test", requires_approval: true
  }]
};

const execute = createGuardedToolExecute({
  tool: "send_message",              // host-owned identity
  effect: "send",                     // host-owned classification
  purpose: "Send a team update",      // fixed purpose for this tool
  resourceFor: args => args.to,       // must match the actual destination
  policy,
  requestApproval: async ({ proposal, proposal_sha256 }, context) =>
    showAndAuthorizeExactProposal(proposal, proposal_sha256, context),
  execute: async (args, context) =>
    sendThroughMyService(args.to, args.body, context)
});

// Hand `execute` to a function-tool definition in your agent framework.
// It returns { protocol, plan, receipt, result? }.
```

`requestApproval` must return `{ approved: true, proposal_sha256 }` for the exact frozen proposal, or refuse. The callback may be omitted for a policy rule that allows an action without approval. If an approval-required rule has no callback, dispatch blocks. The adapter passes the framework's second `execute` argument as `context` to the host callbacks, and calls the tool with the frozen canonical arguments. A host mapping error throws before any tool invocation.

## Rehearse a one-use grant

Run `node pilots/action-boundary/one-shot-grant-demo.mjs` or open the [replay scenario](https://aruintelligence.github.io/aml-core/action-lab.html?scenario=replay). The first invocation uses a local grant; the second attempt with the same grant blocks before the callback. The example sends no message and authenticates no person.

To opt in for a host function tool, keep the grant store and approval issuer **inside the host**:

```js
import { createLocalOneShotGrants } from "./pilots/action-boundary/one-shot-grants.mjs";

const grants = createLocalOneShotGrants(); // One Node process, demonstration only.
const guarded = createGuardedToolExecute({
  tool: "send_message", effect: "send", purpose: "Send a team update",
  resourceFor: args => args.to, policy,
  requestApproval: async (input, context) => {
    if (!await hostAuthenticateAndApprove(input.proposal, input.proposal_sha256, context)) {
      return { approved: false };
    }
    return grants.issue(input.proposal_sha256); // New ID, short expiry.
  },
  consumeApproval: grants.consume,
  execute: async (args, context) => sendThroughMyService(args.to, args.body, context)
});
```

`hostAuthenticateAndApprove` and `sendThroughMyService` are host functions you must implement; the browser and CLI examples only simulate their outcome. The `consumeApproval` hook runs after the proposal digest and rule match, before the callback. It must make an atomic one-use claim bound to the digest and return `true` only once. A false claim blocks with `approval_reused_or_expired`; an error blocks with `approval_consume_error`. A policy change during an asynchronous claim still blocks. The local Map store does not survive restarts or coordinate multiple workers. Use a durable atomic store and your own authenticated approval, time policy, audit, and idempotency controls in a real deployment. An uncertain callback result still consumes the grant and must not be retried automatically.

For a bounded **two-process local-filesystem rehearsal**, run `node pilots/action-boundary/file-grant-race-demo.mjs` and [inspect the recorded race](https://aruintelligence.github.io/aml-core/approval-race.html). `createFileOneShotGrants({ directory: "/absolute/private/host/path" })` exposes async `issue` and `consume` methods with the same hook shape. Its exclusive claim marker coordinates workers sharing one trusted local filesystem; it is not a network or multi-machine store, does not authenticate an approver, and has no long-running cleanup policy. Keep the directory private and supply real host authorization before any external tool.

For the [OpenAI Agents SDK JavaScript function-tool API](https://openai.github.io/openai-agents-js/guides/tools/), install `@openai/agents` and `zod` in your agent app, then attach the `execute` function above:

```js
import { tool } from "@openai/agents";
import { z } from "zod";

const sendMessageTool = tool({
  name: "send_message",
  description: "Send one team update through the host service",
  parameters: z.object({ to: z.string(), body: z.string() }),
  execute
});
```

The SDK [also has native approval interruptions](https://openai.github.io/openai-agents-js/guides/human-in-the-loop/). If you use them, verify the approved item and exact proposal in your own host flow; do not treat a model-supplied digest or a hard-coded `{ approved: true }` as a person's approval. This adapter only wraps **local function tools** configured with it; it does not intercept hosted tools, built-in tools, MCP calls, handoffs, or other execution paths.

## Interpret the result

| Receipt status | Meaning for the host |
|---|---|
| `blocked` | The callback was not invoked. Inspect `reason`; an exact policy rule or matching approval may be missing. |
| `dispatched` | The callback returned. This does not prove the external side effect completed. |
| `unknown` | The callback threw after invocation. The action may already have happened; the wrapper does not retry. |

The plan and receipt share the frozen proposal digest. A change to the destination, body, or declared effect changes the proposal or policy decision. The host still must map the real tool and destination honestly and use its own authentication, replay controls, durable audit storage, and idempotency strategy. Do not infer consent, delivery, or production authorization from SHA-256 or from this example.

For independent reproduction, run the [13-case action boundary challenge](../publications/ACTION_BOUNDARY_CHALLENGE.md) against an implementation maintained outside this repository. This wrapper imports the project reference boundary, so its tests are project-authored evidence only.
