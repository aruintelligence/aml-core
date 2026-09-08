import test from "node:test";
import assert from "node:assert/strict";
import { once } from "node:events";
import { createAmlHttpServer } from "../server/httpServer.js";

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

async function withServer(fn) {
  const server = createAmlHttpServer({ default_profile: "human_first" });
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
