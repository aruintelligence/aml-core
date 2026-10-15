# ĀML locked HTTP render gate pilot

This pilot shows an application applying an ĀML decision to a **local render callback**. It starts the real HTTP service on an ephemeral loopback port with a host-owned locked policy, a temporary bearer token, and an ephemeral Ed25519 signing key. The client generates a fresh 256-bit request nonce, verifies the signed receipt against a separately pinned public-key fingerprint, binds the nonce, intent, and expected context, checks the decision, and only then invokes the callback.

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
| Receipt has no signature | Blocked before callback |
| Receipt has a valid signature from an untrusted key | Blocked before callback |
| Valid signed receipt replayed for a different request nonce | Blocked before callback |
| Valid receipt substituted for another intent | Blocked before callback |
| Effective decision changed outside the receipt | Blocked before callback |
| Shadow response with an effective allow | Blocked before callback |
| Caller tries to select shadow mode | HTTP 403; blocked before callback |
| Evaluation error | Blocked before callback |
| Transport failure | Blocked before callback |
| Callback writes then throws | `unknown`: callback was attempted; no claim of a clean rollback |

The host imports `evaluateLockedHttpAndRender` or `applyLockedHttpDecision` from the public `aml-core` entry point. [`host-gate.mjs`](host-gate.mjs) preserves the old pilot names as aliases. The client sends an intent with a random nonce, enforces a transport deadline and response size limit, rejects duplicate names in raw response JSON, then checks the signed response before using `receipt.selected_render.html`. The host must own the service URL, authentication, trusted context, expected profile, trusted receipt fingerprints, and render callback. Pin fingerprints through a reviewed path independent of the response and rotate them deliberately. It must prevent other application render paths from bypassing this gate. A real integration needs TLS, its own identity/authorization layer, rate limits, accessibility review of suppression, and a policy and rollback owner. See the [public API](../../API.md#evaluatelockedhttpandrenderoptions), [locked HTTP configuration](../../docs/LOCKED_HTTP_POLICY.md), and [security evaluation checklist](../../docs/SECURITY_EVALUATION_CHECKLIST.md).

All requests and callbacks in this pilot stay inside one Node process and its loopback HTTP server. The callback records a string in memory; it does not display a page or touch a customer system. The pinned signing key authenticates the receipt to this local host configuration; it does not prove the server's organizational identity, truthful intent, policy correctness, or HTML safety. The private key is generated for each run and never written to the repository. A real renderer needs its own content handling and CSP review. The bearer token and loopback channel are demonstration controls, not evidence of a production trust boundary. This is project-authored engineering evidence, not independent validation or a sales claim of deployment readiness.

## Try an adversarial comparison

```bash
node pilots/enterprise-http-gate/adversarial.mjs
node pilots/enterprise-http-gate/adversarial.mjs --seed 0123456789abcdef0123456789abcdef
```

This second runner starts three real locked HTTP services on loopback: the expected context/profile, a different consent context, and a different profile. It relays their signed responses through a local test transport that can alter the outer envelope, remove or replace a signature, substitute an intent or context, replay a prior nonce, insert duplicate JSON object names, or exceed a host response limit. Each response is handed to two in-memory hosts: a **deliberately unsafe comparison** that trusts the outer `effective_allowed` flag and HTML, and the public `evaluateLockedHttpAndRender` gate. Seventeen cases assert each callback count and reason; the JSON report records SHA-256 hashes of the HTML seen by each callback without printing HTML, keys, token, context, or full receipts. A fixed seed reproduces intent and injected HTML bytes, while fresh nonces, timestamps, and signing keys make receipt hashes differ between runs.

| Observation in this local run | Meaning |
|---|---|
| Valid allow enters both callbacks; valid suppression enters neither | Positive and negative controls |
| Replacing only the outer HTML enters both callbacks, but their output hashes differ | The verified gate uses the original signed receipt HTML; the unsafe comparison uses the changed outer HTML |
| Fourteen other adverse cases enter the unsafe callback and none enter the verified callback | Those exact mutations are rejected before the verified callback |
| Duplicate names in the outer envelope or signed receipt, including an escaped alias, return `ambiguous_json` | The host rejects the raw wire bytes before applying the signature and decision checks |

Run `node --test test/enterprise-http-gate.test.js` or inspect the `aml-signed-gate-adversarial-<commit>` artifact from the Enterprise Readiness workflow. The example adversary controls the relay, not the pinned private signing key or the host's trust configuration. Before the fix, all three duplicate-key cases reached the verified callback because the JavaScript parser kept the last value; the project-authored Python verifier rejects such source JSON. The unsafe comparison is intentionally flawed, not a measured customer application. Passing these cases cannot establish protection against every attack, browser paint, independent verification, or production readiness.

## Recheck a real HTTP exchange with Python

The project also supplies a separate Python verifier for saved, parsed responses from this locked HTTP service. Install Python 3.12 and `cryptography>=42,<51`, then capture the repository's synthetic allow and consent suppression fixtures into a **new** directory:

```bash
node pilots/enterprise-http-gate/capture.mjs --out /tmp/aml-http-capture-example
python3 independent/python/verify_http_exchange.py \
  /tmp/aml-http-capture-example/exchange-allow.json \
  /tmp/aml-http-capture-example/capsule-allow.json \
  /tmp/aml-http-capture-example/host-expected-allow.json \
  /tmp/aml-http-capture-example/trusted-policy.json
python3 independent/python/verify_http_exchange.py \
  /tmp/aml-http-capture-example/exchange-suppress.json \
  /tmp/aml-http-capture-example/capsule-suppress.json \
  /tmp/aml-http-capture-example/host-expected-suppress.json \
  /tmp/aml-http-capture-example/trusted-policy.json
```

The first report has `verified: true`, `status: "allow"`; the second has `verified: true`, `status: "suppressed"`, and `render_eligible: false`. The verifier compares each response receipt to its evidence capsule, checks the capsule's internal hashes, audit chain, ledger, Ed25519 signature and **separately supplied** fingerprint policy, then binds the signed nonce, intent, profile and context to the host's saved expectation. It checks the HTTP status, server-owned enforcement settings, and effective decision. It reports the signed output hash; it never executes the HTML or trusts the outer `selected_render.html` as output. It exits nonzero on rejected evidence.

Run `node scripts/check-http-exchange-python.mjs` to generate fresh loopback exchanges and exercise 22 cross-runtime cases, including replay, foreign keys, changed receipt content, altered decision, changed context, revocation, and an outer HTML swap. Enterprise Readiness CI uploads the compact `aml-locked-http-python-<commit>` report. The capture creates its own ephemeral key and writes the corresponding fingerprint to a separate file for this local fixture; a real host must provision and review that trust pin independently. Only the project fixtures are used here. The full saved exchanges may contain declared intent and context, so review them before sharing. Neither this project-authored Python implementation nor its passing examples establish an external witness, truthful inputs, live network identity, browser paint, or production fitness.
