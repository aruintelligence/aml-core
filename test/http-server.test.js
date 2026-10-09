import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import http from "node:http";
import fs from "node:fs";
import { once } from "node:events";
import { createAmlHttpServer } from "../server/httpServer.js";
import { signBrandAuthorization } from "../runtime/brandAuthorization.js";

function intent() {
  return {
    transmission: "http_test",
    nodes: [{
      type: "message",
      identifier: "Greeting",
      properties: {
        purpose: "Explain the test clearly.",
        attention_cost: 1,
        restoration_value: 3,
        collects_personal_data: false,
        consent_required: false
      }
    }]
  };
}

function suppressedIntent() {
  return {
    transmission: "http_shadow_test",
    nodes: [{
      type: "message",
      identifier: "Pressure",
      properties: {
        purpose: "Create urgency",
        attention_cost: 5,
        restoration_value: 1
      }
    }]
  };
}

function witnessVector() {
  return JSON.parse(fs.readFileSync(new URL("../independent/python/witness-vector.json", import.meta.url), "utf8"));
}

async function withServer(fn, options = {}) {
  const server = createAmlHttpServer({ default_profile: "human_first", ...options });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const address = server.address();
  try {
    await fn(`http://127.0.0.1:${address.port}`);
  } finally {
    server.close();
    await once(server, "close");
  }
}

test("AML HTTP protects POST routes before reading bodies when authentication is configured", async () => {
  const token = "0123456789abcdef0123456789abcdef0123456789abcdef";
  await withServer(async (base) => {
    const health = await fetch(`${base}/health`);
    assert.equal(health.status, 200);

    const request = (authorization) => fetch(`${base}/v1/deployment/evaluate`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        ...(authorization ? { authorization } : {})
      },
      body: JSON.stringify({ intent: intent() })
    });
    const missing = await request();
    assert.equal(missing.status, 401);
    assert.equal((await missing.json()).error, "unauthorized");
    assert.equal((await request("Bearer wrong")).status, 401);
    const allowed = await request(`Bearer ${token}`);
    assert.equal(allowed.status, 200);
    assert.equal((await allowed.json()).policy_source, "server");
  }, { request_auth: { bearer_token: token }, locked_policy: { profile: "human_first" } });
});

test("AML HTTP masks authentication callback failures", async () => {
  await withServer(async (base) => {
    const response = await fetch(`${base}/v1/deployment/evaluate`, {
      method: "POST", body: "{}"
    });
    assert.equal(response.status, 503);
    assert.equal((await response.json()).error, "authentication_unavailable");
  }, { request_auth: async () => { throw new Error("sensitive session detail"); } });
});

test("AML HTTP health and capabilities endpoints respond", async () => {
  await withServer(async (base) => {
    const health = await fetch(`${base}/health`).then((res) => res.json());
    assert.equal(health.ok, true);
    assert.equal(health.protocol, "aml-http/1");

    const capabilities = await fetch(`${base}/v1/capabilities`).then((res) => res.json());
    assert.equal(capabilities.language, "ĀML — ĀRU Meaning Language");

    const trustRoots = await fetch(`${base}/v1/brand-trust-roots`).then((res) => res.json());
    assert.equal(trustRoots.type, "aml-brand-trust-roots/1");
  });
});

test("AML HTTP evaluate returns a verifiable receipt", async () => {
  await withServer(async (base) => {
    const evaluationResponse = await fetch(`${base}/v1/evaluate`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ intent: intent(), profile: "human_first", context: { attention_budget_remaining: 10 } })
    });
    assert.equal(evaluationResponse.status, 200);
    const evaluation = await evaluationResponse.json();
    assert.equal(evaluation.protocol, "aml-http-evaluation/1");
    assert.equal(evaluation.allowed, true);
    assert.ok(evaluation.receipt.receipt_sha256);

    const verifyResponse = await fetch(`${base}/v1/verify-receipt`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ receipt: evaluation.receipt })
    });
    assert.equal(verifyResponse.status, 200);
    const verification = await verifyResponse.json();
    assert.equal(verification.verified, true);
  });
});

test("AML HTTP deployment endpoint supports shadow rollout", async () => {
  await withServer(async (base) => {
    const response = await fetch(`${base}/v1/deployment/evaluate`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        intent: suppressedIntent(),
        profile: "calm_default",
        mode: "shadow",
        failure_mode: "closed",
        timestamp: "2030-01-01T00:00:00.000Z"
      })
    });
    assert.equal(response.status, 200);
    const body = await response.json();
    assert.equal(body.protocol, "aml-http-deployment-evaluation/1");
    assert.equal(body.mode, "shadow");
    assert.equal(body.aml_allowed, false);
    assert.equal(body.effective_allowed, true);
    assert.equal(body.would_suppress, true);
    assert.ok(body.receipt.receipt_sha256);
  });
});

test("AML HTTP deployment endpoint exposes fail-open versus fail-closed", async () => {
  await withServer(async (base) => {
    const invalidIntent = { transmission: "invalid", nodes: [{ type: "not valid type", properties: {} }] };
    const closedResponse = await fetch(`${base}/v1/deployment/evaluate`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ intent: invalidIntent, failure_mode: "closed" })
    });
    assert.equal(closedResponse.status, 422);
    const closed = await closedResponse.json();
    assert.equal(closed.effective_allowed, false);
    assert.equal(closed.aml_allowed, null);

    const openResponse = await fetch(`${base}/v1/deployment/evaluate`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ intent: invalidIntent, failure_mode: "open" })
    });
    assert.equal(openResponse.status, 422);
    const open = await openResponse.json();
    assert.equal(open.effective_allowed, true);
    assert.equal(open.aml_allowed, null);
  });
});

test("AML HTTP deployment batch preserves aggregate and per-intent evidence", async () => {
  await withServer(async (base) => {
    const response = await fetch(`${base}/v1/deployment/batch`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        intents: [intent(), suppressedIntent()],
        profile: "calm_default",
        mode: "enforce",
        failure_mode: "closed",
        timestamp: "2030-01-01T00:00:00.000Z"
      })
    });
    assert.equal(response.status, 200);
    const body = await response.json();
    assert.equal(body.protocol, "aml-http-deployment-batch/1");
    assert.equal(body.total, 2);
    assert.equal(body.aml_allowed, 1);
    assert.equal(body.aml_suppressed, 1);
    assert.equal(body.results.length, 2);
    assert.equal(typeof body.results[0].receipt_sha256, "string");
  });
});

test("AML HTTP policy canary reports decision changes without choosing policy correctness", async () => {
  await withServer(async (base) => {
    const privacyIntent = {
      transmission: "http_canary",
      nodes: [{
        type: "message",
        identifier: "Collect",
        properties: {
          purpose: "Collect optional personal data",
          attention_cost: 1,
          restoration_value: 4,
          collects_personal_data: true
        }
      }]
    };
    const response = await fetch(`${base}/v1/deployment/canary`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        intent: privacyIntent,
        baseline_profile: "calm_default",
        candidate_profile: "privacy_first",
        context: { privacy_consent: false },
        timestamp: "2030-01-01T00:00:00.000Z"
      })
    });
    assert.equal(response.status, 200);
    const body = await response.json();
    assert.equal(body.protocol, "aml-http-policy-canary/1");
    assert.equal(body.changed_decisions >= 1, true);
    assert.equal(body.candidate_new_suppressions >= 1, true);
    assert.equal(typeof body.baseline.receipt_sha256, "string");
    assert.equal(typeof body.candidate.receipt_sha256, "string");
  });
});

test("AML HTTP verifies a cross-language witness bundle and rejects mutation", async () => {
  await withServer(async (base) => {
    const bundle = witnessVector();
    const validResponse = await fetch(`${base}/v1/verify-witness-bundle`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ bundle, now: "2030-01-01T00:05:00Z" })
    });
    assert.equal(validResponse.status, 200);
    const valid = await validResponse.json();
    assert.equal(valid.protocol, "aml-http-witness-verification/1");
    assert.equal(valid.valid, true);
    assert.equal(valid.reason, "AML_WITNESS_BUNDLE_VALID");

    const mutated = structuredClone(bundle);
    mutated.evidence.receipt.decisions[0].purpose = "tampered-over-http";
    const badResponse = await fetch(`${base}/v1/verify-witness-bundle`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ bundle: mutated, now: "2030-01-01T00:05:00Z" })
    });
    assert.equal(badResponse.status, 422);
    const bad = await badResponse.json();
    assert.equal(bad.valid, false);
  });
});

test("AML HTTP rejects evaluation without intent", async () => {
  await withServer(async (base) => {
    const response = await fetch(`${base}/v1/evaluate`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ profile: "human_first" })
    });
    assert.equal(response.status, 400);
    const body = await response.json();
    assert.equal(body.error, "intent_required");
  });
});

test("AML HTTP official brand verification fails closed for untrusted signer", async () => {
  const { privateKey } = crypto.generateKeyPairSync("ed25519");
  const credential = signBrandAuthorization({
    grantee: "Example Integrator LLC",
    marks: ["ĀML Compatible™"],
    uses: ["official-compatible-badge"]
  }, privateKey.export({ type: "pkcs8", format: "pem" }), { issuer: "ĀRU Intelligence Inc." });

  await withServer(async (base) => {
    const response = await fetch(`${base}/v1/verify-brand-authorization`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ credential })
    });
    assert.equal(response.status, 422);
    const result = await response.json();
    assert.equal(result.official, false);
    assert.equal(result.reason, "untrusted_signing_key");
  }, {
    brand_trust_roots: {
      type: "aml-brand-trust-roots/1",
      owner: "ĀRU Intelligence Inc.",
      status: "unprovisioned",
      active_keys: [],
      revoked_keys: []
    }
  });
});

test("AML HTTP official brand verification succeeds only for configured trusted signer", async () => {
  const { privateKey } = crypto.generateKeyPairSync("ed25519");
  const credential = signBrandAuthorization({
    grantee: "Example Integrator LLC",
    marks: ["ĀML Compatible™"],
    uses: ["official-compatible-badge"]
  }, privateKey.export({ type: "pkcs8", format: "pem" }), { issuer: "ĀRU Intelligence Inc." });

  await withServer(async (base) => {
    const response = await fetch(`${base}/v1/verify-brand-authorization`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ credential })
    });
    assert.equal(response.status, 200);
    const result = await response.json();
    assert.equal(result.valid, true);
    assert.equal(result.official, true);
    assert.equal(result.trust_root.key_id, "http-test-root");
  }, {
    brand_trust_roots: {
      type: "aml-brand-trust-roots/1",
      owner: "ĀRU Intelligence Inc.",
      status: "active",
      active_keys: [{
        key_id: "http-test-root",
        public_key_sha256: credential.public_key_sha256,
        purpose: "test-only"
      }],
      revoked_keys: []
    }
  });
});


test("AML HTTP returns 413 for advertised and streaming oversized bodies", async () => {
  await withServer(async (base) => {
    const advertised = await fetch(`${base}/v1/evaluate`, {
      method: "POST",
      body: "x".repeat(33)
    });
    assert.equal(advertised.status, 413);
    assert.equal((await advertised.json()).error, "request_too_large");

    const streaming = await new Promise((resolve, reject) => {
      const req = http.request(`${base}/v1/evaluate`, { method: "POST" }, (res) => {
        let body = "";
        res.on("data", (chunk) => { body += chunk; });
        res.on("end", () => resolve({ status: res.statusCode, body: JSON.parse(body) }));
      });
      req.on("error", reject);
      req.write("x".repeat(33));
      req.end();
    });
    assert.equal(streaming.status, 413);
    assert.equal(streaming.body.error, "request_too_large");
  }, { max_body_bytes: 32 });
});

test("locked HTTP policy rejects request-selected profile, mode, failure, context, and time", async () => {
  await withServer(async (base) => {
    const post = (route, body) => fetch(`${base}${route}`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body)
    });

    for (const control of [
      { profile: "calm_default" },
      { mode: "shadow" },
      { failure_mode: "open" },
      { context: { consent_granted: true } },
      { timestamp: "2030-01-01T00:00:00.000Z" },
      { max_items: 1000 }
    ]) {
      const response = await post("/v1/deployment/evaluate", { intent: suppressedIntent(), ...control });
      assert.equal(response.status, 403);
      assert.equal((await response.json()).error, "policy_override_forbidden");
    }

    const batchOverride = await post("/v1/deployment/batch", {
      intents: [intent()], mode: "shadow"
    });
    assert.equal(batchOverride.status, 403);
    const direct = await post("/v1/evaluate", { intent: intent() });
    assert.equal(direct.status, 403);
    const canary = await post("/v1/deployment/canary", { intent: intent() });
    assert.equal(canary.status, 403);
  }, { locked_policy: { profile: "human_first", context: { consent_granted: false } } });
});

test("locked HTTP policy enforces server controls and bounds batches", async () => {
  await withServer(async (base) => {
    const post = (route, body) => fetch(`${base}${route}`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body)
    });
    const blocked = await post("/v1/deployment/evaluate", { intent: suppressedIntent() });
    assert.equal(blocked.status, 200);
    const decision = await blocked.json();
    assert.equal(decision.policy_source, "server");
    assert.equal(decision.mode, "enforce");
    assert.equal(decision.failure_mode, "closed");
    assert.equal(decision.effective_allowed, false);
    assert.equal(decision.receipt.profile.id, "human_first");

    const invalid = { transmission: "bad", nodes: [{ type: "not valid type", properties: {} }] };
    const failure = await post("/v1/deployment/evaluate", { intent: invalid });
    assert.equal(failure.status, 422);
    assert.equal((await failure.json()).effective_allowed, false);

    const batch = await post("/v1/deployment/batch", { intents: [suppressedIntent()] });
    assert.equal(batch.status, 200);
    assert.equal((await batch.json()).effective_allowed, 0);
    const oversized = await post("/v1/deployment/batch", { intents: [intent(), suppressedIntent()] });
    assert.equal(oversized.status, 400);
    assert.match((await oversized.json()).error, /AML_BATCH_LIMIT_EXCEEDED/);
  }, { locked_policy: { max_batch_items: 1 } });
});

test("locked HTTP policy fails closed if trusted context is unavailable", async () => {
  await withServer(async (base) => {
    const response = await fetch(`${base}/v1/deployment/evaluate`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ intent: intent() })
    });
    assert.equal(response.status, 503);
    assert.deepEqual(await response.json(), { error: "trusted_context_unavailable" });
  }, { locked_policy: { resolve_context: async () => { throw new Error("private session detail"); } } });
});

test("locked HTTP policy uses a trusted resolver for consent context", async () => {
  const collecting = intent();
  collecting.nodes[0].properties.collects_personal_data = true;
  collecting.nodes[0].properties.consent_required = true;
  await withServer(async (base) => {
    const response = await fetch(`${base}/v1/deployment/evaluate`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ intent: collecting })
    });
    assert.equal(response.status, 200);
    const result = await response.json();
    assert.equal(result.effective_allowed, true);
    assert.equal(result.receipt.context.consent_granted, true);
    assert.equal(result.receipt.context.privacy_consent, true);
  }, {
    locked_policy: {
      resolve_context: async () => ({ consent_granted: true, privacy_consent: true })
    }
  });
});
