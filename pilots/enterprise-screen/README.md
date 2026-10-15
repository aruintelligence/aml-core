# See the signed gate on a local screen

Run from a Git checkout with Node.js 20 or later:

```bash
node pilots/enterprise-screen/server.mjs
```

Open `http://127.0.0.1:4173` and select each proposal. The pricing explanation appears inside an isolated iframe after the signed receipt passes the host gate. The personalization prompt is suppressed because the example's host-owned context has no consent; its HTML is not returned to the browser. A new proposal clears the old frame immediately. Set `AML_SCREEN_PORT` if port 4173 is taken. Stop with Ctrl+C.

## Try a local proposal of your own

Supply one intent file and a separate **host-owned** context file. For example, the bundled personalization fixture blocks with denied consent:

```bash
node pilots/enterprise-screen/server.mjs \
  --intent pilots/enterprise-screen/intent-sensitive.json \
  --context pilots/enterprise-30min/context-denied.json
```

Use `pilots/enterprise-30min/context-allowed.json` to see that same intent allowed under a different context. Then replace the intent path with your own [machine-intent JSON](intent-allowed.json) for one generated interface region. Keep the context file under application control; a model or browser claim of consent is not trusted context. The files are read once when the host starts. The intent file is limited to 64 KiB and 1–20 top-level nodes; the context file is limited to 16 KiB and must contain a JSON object. The host returns an error at startup for oversized or malformed files. The custom mode exposes a single **Your local proposal** button; it does not expose the input files, file paths, signer pin, policy controls, or credentials through the page. An allowed result does send the generated HTML to your local browser, so use data you are permitted to display there. This command starts loopback servers only; it does not upload the files to ĀRU.

This sample runs two loopback servers in one Node process: the locked ĀML HTTP service and a small host web server. The host creates a temporary Ed25519 signing key and bearer token on startup, pins the public-key fingerprint locally, and holds the policy profile, context, and two fixed proposed intents ([pricing](intent-allowed.json), [personalization](intent-sensitive.json)) on the server. The browser selects only `allowed` or `sensitive`; `/api/evaluate` rejects extra fields, including caller-supplied context or mode. The host calls the public `evaluateLockedHttpAndRender` API, checks the nonce-bound signed receipt and effective decision, and returns HTML only if its render callback completed after a verified allow. The page hands that HTML to an iframe with an empty `sandbox` attribute and a restrictive Content Security Policy; it never inserts proposal HTML into the parent document. A block, exchange failure, or new selection clears the frame. The browser displays the receipt SHA-256, never the bearer token, private key, or full receipt.

Verify the host path with:

```bash
node --test test/enterprise-screen.test.js
```

The integration test sends real HTTP requests through both localhost servers. It checks allow and suppression, no HTML on block or outage, rejection of browser policy overrides and unknown fixtures, no direct browser proxy to the service, and page isolation headers. Its custom-flow case checks startup snapshots and separate denied/allowed context files. The [13-case gate pilot](../enterprise-http-gate/README.md) covers tampering, untrusted signers, replay, and callback uncertainty.

This is a project-authored demonstration with temporary credentials, not customer deployment or independent validation. A supplied intent can exercise a local flow, but the service cannot prove that real AI intent declarations are truthful or that a context file reflects a real authenticated session. The signer pin is set up by the same local process for demonstration. Real applications need independently provisioned signer trust, authenticated sessions and consent resolution, TLS, rate limits, content handling and CSP review, key rotation, accessibility handling for suppression, and a single enforced render path. The sandbox and CSP limit this example's HTML; they are not a general sanitizer for arbitrary markup. A server callback saying `rendered` means the HTML was prepared and returned by the host, not that a browser painted it or that a user saw it. See the [locked policy guide](../../docs/LOCKED_HTTP_POLICY.md) and [public gate API](../../API.md#evaluatelockedhttpandrenderoptions).
