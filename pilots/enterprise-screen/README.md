# See the signed gate on a local screen

Run from a Git checkout with Node.js 20 or later:

```bash
node pilots/enterprise-screen/server.mjs
```

Open `http://127.0.0.1:4173` and select each proposal. The pricing explanation appears inside an isolated iframe after the signed receipt passes the host gate. The personalization prompt is suppressed because the example's host-owned context has no consent; its HTML is not returned to the browser. A new proposal clears the old frame immediately. Set `AML_SCREEN_PORT` if port 4173 is taken. Stop with Ctrl+C.

This sample runs two loopback servers in one Node process: the locked ĀML HTTP service and a small host web server. The host creates a temporary Ed25519 signing key and bearer token on startup, pins the public-key fingerprint locally, and holds the policy profile, context, and two fixed proposed intents ([pricing](intent-allowed.json), [personalization](intent-sensitive.json)) on the server. The browser selects only `allowed` or `sensitive`; `/api/evaluate` rejects extra fields, including caller-supplied context or mode. The host calls the public `evaluateLockedHttpAndRender` API, checks the nonce-bound signed receipt and effective decision, and returns HTML only if its render callback completed after a verified allow. The page hands that HTML to an iframe with an empty `sandbox` attribute and a restrictive Content Security Policy; it never inserts proposal HTML into the parent document. A block, exchange failure, or new selection clears the frame. The browser displays the receipt SHA-256, never the bearer token, private key, or full receipt.

Verify the host path with:

```bash
node --test test/enterprise-screen.test.js
```

The integration test sends real HTTP requests through both localhost servers. It checks allow and suppression, no HTML on block or outage, rejection of browser policy overrides and unknown fixtures, no direct browser proxy to the service, and page isolation headers. The [13-case gate pilot](../enterprise-http-gate/README.md) covers tampering, untrusted signers, replay, and callback uncertainty.

This is a project-authored demonstration with fixed inputs and temporary credentials, not customer deployment or independent validation. The generated interface text is a fixture; the service cannot prove that real AI intent declarations are truthful. The signer pin is set up by the same local process for demonstration. Real applications need independently provisioned signer trust, authenticated sessions and consent resolution, TLS, rate limits, content handling and CSP review, key rotation, accessibility handling for suppression, and a single enforced render path. The sandbox and CSP limit this example's HTML; they are not a general sanitizer for arbitrary markup. A server callback saying `rendered` means the HTML was prepared and returned by the host, not that a browser painted it or that a user saw it. See the [locked policy guide](../../docs/LOCKED_HTTP_POLICY.md) and [public gate API](../../API.md#evaluatelockedhttpandrenderoptions).
