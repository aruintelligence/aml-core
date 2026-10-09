# Server-owned HTTP deployment policy

The reference HTTP service normally accepts `profile`, `mode`, `failure_mode`, `context`, and `timestamp` from the caller. That flexibility is useful for demonstrations, but an untrusted caller could request `shadow` or `open`, choose a weaker profile, or claim consent. Do not treat that default surface as an enforcement boundary.

`locked_policy` is an opt-in server configuration for deployment evaluation. The server chooses the policy controls, supplies the runtime context, and records a server timestamp. Request attempts to supply those controls return `403 policy_override_forbidden`, including fields present with a `null` value.

## Local demonstration

```bash
AML_LOCKED_POLICY=1 node bin/aml-serve.js
```

This binds to `127.0.0.1` by default, uses `human_first`, `enforce`, `closed`, and an empty trusted context. Consent-gated content remains suppressed until an embedding application supplies a trusted context resolver. Set `AML_API_TOKEN` for the opt-in [HTTP ingress guard](HTTP_INGRESS_AUTH.md); the CLI flag does not add authentication or TLS by itself.

## Embedding API

```js
import { createAmlHttpServer } from "aml-core";

const server = createAmlHttpServer({
  locked_policy: {
    profile: "human_first",
    mode: "enforce",
    failure_mode: "closed",
    max_batch_items: 50,
    resolve_context: async (req) => {
      // Look up and validate a session through your own trusted middleware.
      // Never copy consent or privacy claims from an unauthenticated request.
      const session = await lookupAuthenticatedSession(req);
      if (!session) throw new Error("session unavailable");
      return {
        consent_granted: session.consent_granted,
        privacy_consent: session.privacy_consent,
        attention_budget_remaining: session.attention_budget_remaining
      };
    }
  }
});
```

`lookupAuthenticatedSession` is an application function, not an ĀML API. A static `context` object may be configured instead of `resolve_context`; the two are mutually exclusive. The server snapshots static context at startup. A resolver error or invalid result returns `503 trusted_context_unavailable` without using caller-supplied context.

In locked mode, `POST /v1/deployment/evaluate` and `/v1/deployment/batch` return `policy_source: "server"`. The batch ceiling comes from `max_batch_items` (default 100). Caller attempts to supply `max_items`, `timestamp`, `profile`, `mode`, `failure_mode`, or `context` are rejected. `POST /v1/evaluate` and `/v1/deployment/canary` are disabled in this mode. Receipt and witness verification endpoints remain available.

## Agent UI and governance stream gateways

The same opt-in `locked_policy` option is available in `createAgentUiGateway` and `createGovernanceStreamGateway`. The Agent UI gateway rejects caller-supplied `profile`, `mode`, `failure_mode`, `context`, and `timestamp` (even `null`), resolves server context, and returns `policy_source: "server"`. The stream gateway rejects those controls in the open message and each subsequent message, rejects policy transition messages entirely, and reports `policy_source: "server"` in its accepted open event. An invalid stream message emits an `aml-governance-stream-error/1` event and ends the stream; a successful stream still returns NDJSON with HTTP 200.

```bash
AML_LOCKED_POLICY=1 AML_API_TOKEN="$AML_API_TOKEN" node bin/aml-agent-ui-serve.js
AML_LOCKED_POLICY=1 AML_API_TOKEN="$AML_API_TOKEN" node bin/aml-governance-stream-serve.js
```

These CLIs use `calm_default`, `enforce`, `closed`, and empty trusted context when locked. Embedding applications can pass a trusted `resolve_context` callback in `locked_policy`, just as with the main server. Their locked settings are independent of the main service; configure each gateway you expose. The stream protocol still accepts untrusted intent nodes, so inspect decisions before rendering and enforce appropriate upload and connection limits at the edge.

The caller still supplies **intent**, which must be treated as untrusted input. The application must use `effective_allowed` before rendering and must prevent alternate render paths that bypass this service. This option does not provide authentication, authorization, TLS, rate limiting, secure session validation, or proof that declared intent is truthful. Configure ingress authentication separately and review the remaining controls with the [security evaluation checklist](SECURITY_EVALUATION_CHECKLIST.md) before production use.
