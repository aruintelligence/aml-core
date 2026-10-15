# ĀML locked HTTP render gate pilot

This pilot shows an application applying an ĀML decision to a **local render callback**. It starts the real HTTP service on an ephemeral loopback port with a host-owned locked policy and a temporary bearer token. The client verifies a receipt, binds it to the submitted intent and expected context, checks the decision, and only then invokes the callback.

From a Git checkout with Node.js 20 or later:

```bash
node pilots/enterprise-http-gate/run.mjs
```

The command exits nonzero if any asserted outcome changes. It prints a compact JSON report with case results, receipt hashes where available, the Git revision, and the number of local callback entries. It does not print the bearer token, HTML, full receipts, or fixture context.

| Case | Expected host result |
|---|---|
| Verified allow | One completed callback |
| Missing consent | Suppressed before callback |
| Receipt content changed after evaluation | Blocked before callback |
| Valid receipt substituted for another intent | Blocked before callback |
| Effective decision changed outside the receipt | Blocked before callback |
| Shadow response with an effective allow | Blocked before callback |
| Caller tries to select shadow mode | HTTP 403; blocked before callback |
| Evaluation error or transport failure | Blocked before callback |
| Callback writes then throws | `unknown`: callback was attempted; no claim of a clean rollback |

The reusable host sample is [`host-gate.mjs`](host-gate.mjs). Its `evaluateAndGate` function sends an intent to a host-configured service; `applyVerifiedDecision` checks the response before using `receipt.selected_render.html`. The host must own the service URL, authentication, trusted context, expected profile, and render callback. It must prevent other application render paths from bypassing this gate. A real integration needs TLS, its own identity/authorization layer, rate limits, accessibility review of suppression, and a policy and rollback owner. See [locked HTTP configuration](../../docs/LOCKED_HTTP_POLICY.md) and the [security evaluation checklist](../../docs/SECURITY_EVALUATION_CHECKLIST.md).

All requests and callbacks in this pilot stay inside one Node process and its loopback HTTP server. The callback records a string in memory; it does not display a page or touch a customer system. Receipt verification checks internal integrity and bindings, not the identity of the server or HTML safety. A real renderer needs its own content handling and CSP review. The bearer token and loopback channel are demonstration controls, not evidence of a production trust boundary. This is project-authored engineering evidence, not independent validation or a sales claim of deployment readiness.
