import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
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
