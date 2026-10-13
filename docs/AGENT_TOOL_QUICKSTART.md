# Put an ĀML boundary around one agent function tool

[Start with the visual agent-tool build path](https://aruintelligence.github.io/aml-core/agent-start.html) for the local rehearsal command, expected outcomes, and a host wiring sketch.

This experimental adapter wraps a host-owned `execute` callback. It produces a proposed-action plan and dispatch receipt for one function-tool call. The host supplies the actual policy, destination mapping, approval callback, and tool implementation.

## Run a 30-second local rehearsal

From this repository:

```bash
node pilots/action-boundary/guarded-tool-demo.mjs
```

The first fixture has an exact policy rule and a **simulated** approval; its callback returns a `would_send_to` object. The second changes the destination and is blocked before the callback. There is no network request, message delivery, or human authentication.

For the fifteen-case host rehearsal, list the case IDs and ordered outcomes, then inspect one case:

```bash
node pilots/action-boundary/guarded-tool-rehearsal.mjs --list
node pilots/action-boundary/guarded-tool-rehearsal.mjs --case claim_revoked
node pilots/action-boundary/guarded-tool-rehearsal.mjs --check
```

The list prints one tab-separated ID and outcome sequence per fixture; a two-attempt case prints both statuses in order. The `mapper_mutated` case prints `pre-plan error`: its host mapper changes its argument snapshot, so the adapter throws before a plan or receipt exists. These local fixture callbacks are not human approvals, provider calls, delivery evidence, or proof of production safety. An `unknown` receipt may follow a side effect; do not silently retry it.

The [host allow case](https://aruintelligence.github.io/aml-core/agent-start.html?case=host_allow#rehearsal) shows an exact rule with `requires_approval: false`: one local callback returns with zero approval requests and zero claim attempts. Only the host can choose that policy; the fixture is not a recommendation to waive approval for a real send.

The [approval hook error case](https://aruintelligence.github.io/aml-core/agent-start.html?case=approval_hook_error#rehearsal) writes one in-memory approval fixture marker just before the hook throws. The tool receipt is `blocked`, with no claim or tool callback. This is not a human approval or a durable grant; a real host must reconcile its authorization store rather than infer that no approval-state change occurred.

On the visual builder, **Copy fixture JSON** copies the selected case in the same shape as `--case`, including its project-authored provenance and scope. Include your checkout commit when sharing a reproduction; the copied fixture is not evidence of a real approval or delivery.

The [declined approval case](https://aruintelligence.github.io/aml-core/agent-start.html?case=approval_declined#rehearsal) requests a fixture decision and receives a refusal. The receipt blocks before any claim or tool callback. A refusal is not a grant; a later attempt needs its own authenticated decision.

## Wrap your own function tool

This is the host-side shape. The host must implement `showAndAuthorizeExactProposal`, `consumeHostGrantOnce`, and `sendThroughMyService` with its own authentication, durable claim storage, and authorization. Do not use the demo's automatic approval in a real integration.

```js
import { createGuardedToolExecute } from "./pilots/action-boundary/guarded-tool.mjs";

async function consumeHostGrantOnce(input, context) {
  throw new Error("Atomically consume the host-issued grant in durable storage");
}

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
  consumeApproval: (input, context) => consumeHostGrantOnce(input, context),
  execute: async (args, context) =>
    sendThroughMyService(args.to, args.body, context)
});

// Hand `execute` to a function-tool definition in your agent framework.
// It returns { protocol, plan, receipt, result? }.
```

`requestApproval` must return `{ approved: true, proposal_sha256 }` for the exact frozen proposal, or refuse, and identify a host-issued one-use grant. The `consumeApproval` hook must atomically claim that grant, bound to the digest, and return exactly `true` once. The placeholder above throws, so a copied sketch cannot dispatch until the host implements the claim. The approval callback may be omitted for a policy rule that allows an action without approval. If an approval-required rule has no callback, dispatch blocks. The adapter passes the framework's second `execute` argument as `context` to the host callbacks, and calls the tool with the frozen canonical arguments. A host mapping error throws before an action plan or dispatch receipt exists and before any tool invocation. Handle it in the host error path rather than fabricating a blocked receipt.

The [mapper mutation case](https://aruintelligence.github.io/aml-core/agent-start.html?case=mapper_mutated#rehearsal) records a pre-plan exception and zero approval requests, claim attempts, and tool callbacks. Its `adapter_error` is an observed local exception, not a receipt reason.

The adapter captures the tool arguments once before calling `resourceFor`. Keep that host mapper synchronous and read-only: it receives a snapshot, and a mutation throws before approval or dispatch. The policy resource and provider callback must describe the same destination. If your provider callback adds recipients or rewrites a request, use the prepared request adapters below so the complete provider request is checked before dispatch.

**If your mail callback uses CC or BCC**, the To-only `resourceFor` above is incomplete for that expanded callback. Use the [complete-recipient mail adapter](../pilots/action-boundary/MAIL_GUARDED_TOOL.md) for its narrow `to`/`cc`/`bcc` schema. The [seven-case integration lab](https://aruintelligence.github.io/aml-core/mail-tool-integration.html?case=added_bcc#cases) runs both function-tool wrappers with a BCC-capable in-memory callback. It does not send mail or approve anything.

**If the host changes the request before calling its provider**, construct the full request before the policy check with the [prepared mail adapter](../pilots/action-boundary/PREPARED_MAIL_TOOL.md). The [eight-case lab](https://aruintelligence.github.io/aml-core/prepared-mail-lab.html?case=route_bcc#cases) shows a BCC appended after an earlier check reaching one local provider callback; preparing it first blocks that callback under the same recipient rule. A changed body also invalidates a fixed original proposal digest when approval is required. The host sender must submit exactly the prepared fields.

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

The [host rehearsal](https://aruintelligence.github.io/aml-core/agent-start.html?case=claim_revoked#rehearsal) includes a claim that succeeds while the rule is revoked. Its receipt is `blocked` with zero callback invocations, and the grant remains spent. A retry needs a fresh policy decision and a new authenticated grant; the old claim is not restored.

The [claim-hook error case](https://aruintelligence.github.io/aml-core/agent-start.html?case=claim_hook_unknown#rehearsal) spends a fixture claim just before the hook throws. The receipt is `blocked` with zero tool callback invocations, but the grant is spent in this local fixture. A real host must reconcile its durable grant store after a claim error; the blocked receipt alone cannot establish whether the grant remains available.

The [unknown then replay case](https://aruintelligence.github.io/aml-core/agent-start.html?case=unknown_then_replay#rehearsal) starts with a fixture callback error and an `unknown` receipt. A second attempt using the same one-use fixture claim state blocks before callback entry. The fixture makes no provider call; a real host must reconcile the uncertain outcome and use operation idempotency before considering any new authorization.

The uncertain callback cases write an in-memory fixture marker immediately before throwing. Their `fixture_state_changes: 1` and hook trace make the local sequence visible: a receipt can be `unknown` after a local state change. That marker is not an external send, delivery, or evidence about a provider.

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

