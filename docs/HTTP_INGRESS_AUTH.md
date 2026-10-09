# HTTP ingress authentication

The reference HTTP service, Agent UI gateway, and governance stream gateway accept an optional `request_auth` option. When configured, each gateway checks POST requests before reading the body or opening a response stream. Missing or invalid credentials return `401 unauthorized`; static bearer authentication also sends `WWW-Authenticate: Bearer realm="aml"`. Authentication callback failures or timeouts return `503 authentication_unavailable` without exposing the callback error. `GET /health` remains public. The main service also leaves its public capabilities and brand trust roots GET endpoints available.

## CLI with a bearer token

Set a secret of 32–4096 ASCII bearer-token characters in the process environment, then start any of the three servers with `AML_API_TOKEN`. The example generates a random base64url secret:

```bash
export AML_API_TOKEN="$(node -e "process.stdout.write(require('node:crypto').randomBytes(32).toString('base64url'))")"
AML_LOCKED_POLICY=1 node bin/aml-serve.js
# In another terminal with the same secret:
curl -H "Authorization: Bearer $AML_API_TOKEN" \
  -H "Content-Type: application/json" \
  --data @deployment-request.json \
  http://127.0.0.1:8787/v1/deployment/evaluate
```

`bin/aml-agent-ui-serve.js` and `bin/aml-governance-stream-serve.js` use the same variable, with their own ports. An invalid token fails server startup; it is never printed by the CLI. The default bind address is loopback. When exposing a service over a network, terminate TLS in a trusted reverse proxy, protect the token in a secret store, and limit access and request rates there. Keep the proxy from forwarding untrusted `Authorization` headers when it supplies its own identity.

The `AML_LOCKED_POLICY=1` setting is separate: it fixes policy controls for the main deployment evaluation endpoints and, independently, for each adjacent gateway started with that flag. Use both settings when testing an authenticated enforcement boundary. See [server-owned policy](LOCKED_HTTP_POLICY.md) for each route's behavior.

## Embedding API

```js
import { createAmlHttpServer } from "aml-core";

const server = createAmlHttpServer({
  request_auth: { bearer_token: process.env.AML_API_TOKEN },
  locked_policy: { profile: "human_first" }
});
```

For an application session or an identity-aware proxy, supply an async callback instead. It receives the Node `IncomingMessage` and an optional second argument `{ signal }`, and must return exactly `true` for an authorized request. `false` (or any other result) denies it. Exceptions fail closed with a generic 503. The callback should validate the identity through a trusted source, enforce the needed permission for the requested route, and never trust caller-provided identity headers without proxy controls.

```js
const server = createAmlHttpServer({
  auth_timeout_ms: 2000,
  request_auth: async (req, { signal }) => {
    const session = await lookupAuthenticatedSession(req, { signal });
    return session?.permissions.includes("aml:evaluate") === true;
  },
  locked_policy: {
    profile: "human_first",
    resolve_context: async (req) => contextFromTrustedSession(req)
  }
});
```

The callback deadline defaults to 5000 ms for all three gateways. `auth_timeout_ms` must be a positive safe integer. A deadline returns 503 and aborts the supplied signal. Pass that signal to network/database clients that support cancellation; a callback that ignores it may continue its own work after the HTTP request has ended. The bearer-token comparison does not need an application callback deadline. Configure reverse-proxy connection and rate limits separately.

## Concurrent request ceiling

Each gateway admits at most 100 concurrent POST requests by default. Configure `max_inflight_requests` as a positive safe integer on `createAmlHttpServer`, `createAgentUiGateway`, or `createGovernanceStreamGateway` to match available capacity. A request beyond the ceiling receives `503 { "error": "server_busy" }`, `Retry-After: 1`, and a closing connection before authentication or body evaluation. The Agent UI response also includes its usual error protocol. Slots are released when the response finishes or the client disconnects; an open governance stream retains a slot until it ends. This is per server instance and does not coordinate capacity across replicas. Set network-wide limits and rate controls at the edge.

The static bearer option compares SHA-256 digests with a timing-safe equality check, rejects duplicate `Authorization` headers, and accepts the [RFC 6750](https://www.rfc-editor.org/rfc/rfc6750) `b64token` alphabet (`A–Z`, `a–z`, `0–9`, `-._~+/` with optional trailing `=`). It is suitable for a controlled service boundary, not per-user authorization. This option does not provide TLS, token rotation, rate limiting, audit logging, SSO, or verification that declared intent is truthful. See [server-owned policy](LOCKED_HTTP_POLICY.md) and the [security evaluation checklist](SECURITY_EVALUATION_CHECKLIST.md).
