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
    resolve_context_timeout_ms: 2000,
    resolve_context: async (req, { signal }) => {
      // Look up and validate a session through your own trusted middleware.
      // Never copy consent or privacy claims from an unauthenticated request.
      const session = await lookupAuthenticatedSession(req, { signal });
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

`lookupAuthenticatedSession` is an application function, not an ĀML API. A static `context` object may be configured instead of `resolve_context`; the two are mutually exclusive. The server snapshots static context at startup. A resolver error, timeout, or invalid result returns `503 trusted_context_unavailable` without using caller-supplied context. The resolver deadline defaults to 5000 ms for all three gateways; `resolve_context_timeout_ms` must be a positive safe integer. A deadline aborts the optional `{ signal }` passed to the callback. Forward it to cancellable database/network operations. A callback that ignores the signal can continue its own work after the HTTP response ends.

## Opt-in signed HTTP receipts

A digest alone does not authenticate a response producer: someone who can replace a receipt can compute a new digest. For the locked main HTTP service, configure `receipt_signing` with a host-owned Ed25519 private key and signer label:

```js
const server = createAmlHttpServer({
  locked_policy: { profile: "human_first", mode: "enforce", failure_mode: "closed",
    resolve_context: trustedContextResolver },
  request_auth: { bearer_token: process.env.AML_API_TOKEN },
  receipt_signing: { private_key_pem: process.env.AML_RECEIPT_PRIVATE_KEY_PEM,
    signer: "my-service" }
});
```

The key must be supplied privately by the embedding host; this example does not provision or publish one. Signing requires `locked_policy` and a valid Ed25519 private key at server startup. Clients must send a new, unpredictable 32-byte nonce encoded as 64 lowercase hexadecimal characters in `request_nonce` alongside `intent` or `intents`. Missing or malformed nonces return HTTP 400 before trusted context resolution. Successful single and batch evaluations bind the nonce into each receipt hash and attach a v1.1 Ed25519 signature. Signing failure returns HTTP 503 with no evaluation receipt.

The host should verify the signature **and** match its public-key fingerprint against a trust list provisioned outside the response, then match `receipt.request_nonce` to its outstanding request. It must also bind the receipt to the intended input, profile, context, and effective decision. [`pilots/enterprise-http-gate`](../pilots/enterprise-http-gate/README.md) runs that flow locally. A new nonce blocks replay of an old response into another request; this stateless service cannot stop a host that reuses a nonce or allows another render path around its gate. Plan key rotation and revocation, protect the private key, and use TLS and host authorization in a real deployment. This option signs only deployment evaluation and batch receipts on the main HTTP service; it does not sign `/v1/evaluate`, Agent UI, or governance stream responses.

In locked mode, `POST /v1/deployment/evaluate` and `/v1/deployment/batch` return `policy_source: "server"`. The batch ceiling comes from `max_batch_items` (default 100). Caller attempts to supply `max_items`, `timestamp`, `stream_id`, `stream_ids`, `profile`, `mode`, `failure_mode`, or `context` are rejected. Each locked single evaluation and each locked batch item receives a fresh server-generated audit stream UUID, including repeated identical intents in one batch. The ID distinguishes evaluation records; it does not authenticate a caller or prove that declared intent is truthful. Direct `evaluateInterfaceBatch` calls remain deterministic with fixed inputs and time unless the trusted host supplies a unique `stream_ids` array with one nonempty ID per intent. `POST /v1/evaluate` and `/v1/deployment/canary` are disabled in this mode. Receipt and witness verification endpoints remain available.

With or without `locked_policy`, the HTTP service applies the configured server-owned batch ceiling before resolving trusted context or evaluating intents. Oversized batches return HTTP 413 with `batch_limit_exceeded`. A caller cannot raise the unlocked ceiling with `max_items`; configure `max_batch_items` on `createAmlHttpServer` to change that ceiling (default 100). Locked mode uses its own `locked_policy.max_batch_items` (default 100). The Agent UI gateway separately limits an envelope to 256 components by default; set `max_components` on `createAgentUiGateway` for a different server-owned limit. Oversized Agent UI envelopes return HTTP 413.

## Agent UI and governance stream gateways

The same opt-in `locked_policy` option is available in `createAgentUiGateway` and `createGovernanceStreamGateway`. The Agent UI gateway rejects caller-supplied `profile`, `mode`, `failure_mode`, `context`, `timestamp`, `stream_id`, and `stream_ids` (even `null`), resolves server context, and returns `policy_source: "server"`. Each component evaluation gets a fresh server-generated audit stream UUID. The stream gateway rejects policy controls and caller-supplied audit IDs in the open message and each subsequent message, rejects policy transition messages entirely, and reports `policy_source: "server"` in its accepted open event. Each accepted node receives a fresh server-generated audit stream UUID. Direct local `evaluateAgentUI` calls remain reproducible with fixed inputs and time unless the trusted host supplies unique `stream_ids`; direct `createGovernanceStreamSession` calls remain reproducible unless the host supplies a `stream_id_factory`. These IDs distinguish records, not caller identity or intent truthfulness. An invalid message after the open event emits an `aml-governance-stream-error/1` event and ends the NDJSON stream; errors before acceptance return JSON with an HTTP error status.

```bash
AML_LOCKED_POLICY=1 AML_API_TOKEN="$AML_API_TOKEN" node bin/aml-agent-ui-serve.js
AML_LOCKED_POLICY=1 AML_API_TOKEN="$AML_API_TOKEN" node bin/aml-governance-stream-serve.js
```

These CLIs use `calm_default`, `enforce`, `closed`, and empty trusted context when locked. Embedding applications can pass a trusted `resolve_context` callback in `locked_policy`, just as with the main server. Their locked settings are independent of the main service; configure each gateway you expose. The stream protocol still accepts untrusted intent nodes, so inspect decisions before rendering. The gateway defaults to a 256 KiB line, 8 MiB upload, and 1000 nonempty messages; configure `max_line_bytes`, `max_stream_bytes`, and `max_messages` for your deployment. The HTTP gateway waits for response drain before reading the next message and stops writing when the client disconnects. Enforce connection and rate limits at the edge.

The caller still supplies **intent**, which must be treated as untrusted input. The application must use `effective_allowed` before rendering and must prevent alternate render paths that bypass this service. This option does not provide authentication, authorization, TLS, rate limiting, secure session validation, or proof that declared intent is truthful. Configure ingress authentication separately and review the remaining controls with the [security evaluation checklist](SECURITY_EVALUATION_CHECKLIST.md) before production use.
