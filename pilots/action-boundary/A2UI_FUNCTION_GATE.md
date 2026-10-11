# A2UI v1.0 function call → ĀML action gate

[Open the nine-case visual lab](https://aruintelligence.github.io/aml-core/a2ui-function-lab.html?case=changed_destination#cases) · [Read the A2UI v1.0 specification](https://a2ui.org/specification/v1.0-a2ui/)

The [A2UI v1.0 `callRendererFunction` message](https://a2ui.org/specification/v1.0-a2ui/) asks a renderer to invoke a catalog function. Its catalog's `allowedCallers` controls whether an agent may call it. ĀML's optional host action gate then checks **which exact tool, effect, destination, purpose, and arguments** are about to reach an external callback. This pilot covers one host-owned function entry and one action, so the two decisions stay visible.

Run from the repository root with Node 22:

```bash
node pilots/action-boundary/a2ui-function-demo.mjs
node --test test/action-boundary-a2ui-gate.test.js
node scripts/build-a2ui-function-report.mjs --check
```

The demo's `exact` call returns a `rendererFunctionResponse.value` and an AML `dispatched` receipt after one **simulated** callback. The `changed` call has the same catalog function but an outside destination; it returns `rendererFunctionResponse.error` with `ACTION_BLOCKED`, an AML `no_exact_rule` receipt, and zero extra callbacks. The nine-case report also exercises a renderer-only entry, unknown catalog/function, invalid arguments, stale approval, mutation while awaiting approval, and an uncertain callback.

The host supplies `createA2UIFunctionGate({ catalogId, functionName, allowedCallers, validateArgs, tool, effect, purpose, resourceFor, policy, requestApproval, execute })`. The first four values must come from the renderer's **trusted active catalog and schema**, and the action mapping, policy, approval, and callback must come from the host. The agent supplies only the A2UI call envelope and its arguments. Pass the envelope to the returned handler; deliver its `response` through the renderer's A2UI transport, and retain its separate `aml` plan/receipt for inspection. Use `consumeApproval` for an atomic one-use claim when a real host needs replay control.

```js
const { response, aml } = await handleAgentFunctionCall({
  version: "v1.0",
  callRendererFunction: {
    functionCallId: "send_1",
    callFunction: {
      call: "sendMessage",
      catalogId: "https://example.test/catalog/action.json",
      args: { to: "team@example.test", body: "Build passed." }
    }
  }
});
```

The handler rejects an unregistered or `rendererOnly` function with A2UI's top-level `INVALID_FUNCTION_CALL` error. Once catalog authorization passes, an AML denial becomes a `rendererFunctionResponse.error` with `ACTION_BLOCKED`; a thrown callback becomes `EXECUTION_FAILED` and retains an `unknown` AML receipt. The response echoes `functionCallId`. A missing usable ID throws before handling because the renderer cannot correlate a response.

**Integration limits.** This is a Node host-side example, not a renderer, A2UI conformance suite, official A2UI adapter, or replacement for A2UI's catalog enforcement. The host must implement session initiation/version routing, active catalog lookup, full catalog schema validation, ID uniqueness and replay policy, surface and UI action handling, transport, user authentication, trusted approval, effect authorization, and delivery reconciliation. The supplied validator and approval in the demo are deliberately local simulations. `dispatched` means the callback returned; it does not prove an external side effect completed. If callback status is `unknown`, investigate the real external system before authorizing a fresh operation. Existing framework approvals and guardrails can coexist with this narrower exact-action receipt.
