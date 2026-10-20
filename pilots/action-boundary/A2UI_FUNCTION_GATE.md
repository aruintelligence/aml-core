# A2UI v1.0 candidate function call → ĀML action gate

[Open the nine-case visual lab](https://aruintelligence.github.io/aml-core/a2ui-function-lab.html?case=changed_destination#cases) · [See the two-process replay](https://aruintelligence.github.io/aml-core/a2ui-worker-replay.html) · [Read the A2UI v1.0 candidate specification](https://a2ui.org/specification/v1.0-a2ui/)

The [A2UI v1.0 `callRendererFunction` message](https://a2ui.org/specification/v1.0-a2ui/) asks a renderer to invoke a catalog function. Its catalog's `allowedCallers` controls whether an agent may call it. ĀML's optional host action gate then checks **which exact tool, effect, destination, purpose, and arguments** are about to reach an external callback. This pilot covers one host-owned function entry and one action, so the two decisions stay visible.

Run from the repository root with Node 22:

```bash
node pilots/action-boundary/a2ui-function-demo.mjs
node --test test/action-boundary-a2ui-gate.test.js
node scripts/build-a2ui-function-report.mjs --check
node scripts/build-a2ui-invocation-replay-report.mjs --check
node --test test/a2ui-file-invocation.test.js
node scripts/build-a2ui-worker-report.mjs --check
```

The demo's `exact` call returns a `rendererFunctionResponse.value` and an AML `dispatched` receipt after one **simulated** callback. The `replay` uses the same ID in the same trusted host session and gets top-level `INVALID_FUNCTION_CALL` before another callback. The `changed` call has a new ID but an outside destination; it returns `rendererFunctionResponse.error` with `ACTION_BLOCKED`, an AML `no_exact_rule` receipt, and zero extra callbacks. The nine-case action report also exercises a renderer-only entry, unknown catalog/function, invalid arguments, stale approval, mutation while awaiting approval, and an uncertain callback.

The host supplies `createA2UIFunctionGate({ catalogId, functionName, allowedCallers, validateArgs, claimInvocation, tool, effect, purpose, resourceFor, policy, requestApproval, execute })`. The first four values must come from the renderer's **trusted active catalog and schema**. The action mapping, claim store, policy, approval, and callback must come from the host. The agent supplies only the A2UI call envelope and its arguments. Pass the envelope and **trusted host context** to the returned handler; deliver its `response` through the renderer's A2UI transport, and retain its separate `aml` plan/receipt and `invocation` status for inspection.

`claimInvocation({ functionCallId }, context)` is now required. It must atomically return exactly `true` for the first use of an ID in the host session, `false` for reuse, or throw on store failure. The bridge captures the authorized function object once, freezes its arguments before schema validation, validates a separate copy, and sends the original frozen bytes to the action boundary after the claim. A changing getter cannot swap in unvalidated arguments, and a validator cannot edit the dispatched payload. A reused ID returns top-level `INVALID_FUNCTION_CALL` without an AML dispatch or callback; a store failure returns `EXECUTION_FAILED` without invoking the callback. The ID is **agent-supplied**, so derive the session scope only from authenticated host context. The included `createLocalA2UIInvocationClaims({ sessionFor })` is process-local and capacity-bounded; production needs a persistent atomic claim shared by workers and stable for the session lifetime. This is an experimental API change from the prior bridge, which did not require a claim and allowed the same ID to reach the callback twice.

For workers sharing a trusted **local filesystem**, `createFileA2UIInvocationClaims({ directory, sessionFor })` supplies that atomic claim. Provision an absolute, private (`0700`), host-owned directory first and keep it intact for the entire session lifetime. Pass its `.claim` to the gate in every worker. The module rejects missing, symlinked, group/world-accessible, or replaced directories; it never recreates a lost directory during a claim. It hashes the exact JSON tuple `[trustedSessionId, agentFunctionCallId]` into a claim filename and uses exclusive creation plus file/directory sync. A repeated ID returns `false`, including after a worker restart. Keep worker and storage access under one trusted host account. A same-UID attacker or a host that discards and re-provisions the directory after restart can bypass this local model. Do not use it as a network filesystem or multi-machine coordination guarantee.

```js
import { createFileA2UIInvocationClaims } from "./file-a2ui-invocation-claims.mjs";
const claims = createFileA2UIInvocationClaims({
  directory: hostProvisionedPrivateDirectory,
  sessionFor: trustedContext => trustedContext.authenticatedSessionId
});
// createA2UIFunctionGate({ ...hostCatalogAndPolicy, claimInvocation: claims.claim })
```

```js
const { response, aml, invocation } = await handleAgentFunctionCall({
  version: "v1.0",
  callRendererFunction: {
    functionCallId: "send_1",
    callFunction: {
      call: "sendMessage",
      catalogId: "https://example.test/catalog/action.json",
      args: { to: "team@example.test", body: "Build passed." }
    }
  }
}, { sessionId: trustedRendererSessionId });
```

The handler rejects an unregistered or `rendererOnly` function with A2UI's top-level `INVALID_FUNCTION_CALL` error. Once catalog authorization and the ID claim pass, an AML denial becomes a `rendererFunctionResponse.error` with `ACTION_BLOCKED`; a thrown callback becomes `EXECUTION_FAILED` and retains an `unknown` AML receipt. The response echoes `functionCallId`. A missing usable ID throws before handling because the renderer cannot correlate a response. A policy-blocked invocation still spends its ID; a new ID represents a new attempt that needs its own authorization.

Three separate claims serve different purposes: `claimInvocation` rejects a repeated A2UI correlation ID within a trusted renderer session; optional `consumeApproval` atomically claims an authenticated approval grant for the exact proposal digest; and the optional [host-generated operation ledger](file-dispatch-ledger.mjs) suppresses blind retry of a particular external operation. Do not derive an operation ID from the agent's `functionCallId`. None of these alone proves delivery or prevents a separately authorized new action with a new ID.

**Integration limits.** A2UI v1.0 is a candidate specification; this is a Node host-side example, not a renderer, A2UI conformance suite, official A2UI adapter, or replacement for A2UI's catalog enforcement. The host must implement session initiation/version routing, active catalog lookup, full catalog schema validation, persistent ID uniqueness and replay policy across its workers, surface and UI action handling, transport, user authentication, trusted approval, effect authorization, and delivery reconciliation. The two-process test uses simulated approval and callbacks; it establishes no external effect. `dispatched` means the callback returned; it does not prove an external side effect completed. If callback status is `unknown`, investigate the real external system before authorizing a fresh operation. Existing framework approvals and guardrails can coexist with this narrower exact-action receipt.
