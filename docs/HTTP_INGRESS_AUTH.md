# HTTP ingress authentication

The reference HTTP service, Agent UI gateway, and governance stream gateway accept an optional `request_auth` option. When configured, each gateway checks POST requests before reading the body or opening a response stream. Missing or invalid credentials return `401 unauthorized`; authentication callback failures return `503 authentication_unavailable` without exposing the callback error. `GET /health` remains public. The main service also leaves its public capabilities and brand trust roots GET endpoints available.

## CLI with a bearer token

Set a secret of at least 32 non-whitespace UTF-8 bytes in the process environment, then start any of the three servers with `AML_API_TOKEN`:

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

For an application session or an identity-aware proxy, supply an async callback instead. It receives the Node `IncomingMessage` and must return exactly `true` for an authorized request. `false` (or any other result) denies it. Exceptions fail closed with a generic 503. The callback should validate the identity through a trusted source, enforce the needed permission for the requested route, and never trust caller-provided identity headers without proxy controls.

```js
const server = createAmlHttpServer({
  request_auth: async (req) => {
    const session = await lookupAuthenticatedSession(req);
    return session?.permissions.includes("aml:evaluate") === true;
  },
  locked_policy: {
    profile: "human_first",
    resolve_context: async (req) => contextFromTrustedSession(req)
  }
});
```

The static bearer option compares SHA-256 digests with a timing-safe equality check, rejects duplicate `Authorization` headers, and requires a 32–4096 byte token. It is suitable for a controlled service boundary, not per-user authorization. This option does not provide TLS, token rotation, rate limiting, audit logging, SSO, or verification that declared intent is truthful. See [server-owned policy](LOCKED_HTTP_POLICY.md) and the [security evaluation checklist](SECURITY_EVALUATION_CHECKLIST.md).
