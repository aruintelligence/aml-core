import test from "node:test";
import assert from "node:assert/strict";
import { createHash, generateKeyPairSync, sign, verify } from "node:crypto";
import { evaluateLockedHttpAndRender, executeAccountableIntent,
  signExecutionReceipt } from "../index.js";

const intent = { transmission: "host_gate_test", nodes: [{ type: "message", identifier: "continue",
  properties: { purpose: "Let the person continue", attention_cost: 1, restoration_value: 3 } }] };

function options(fetchImpl, render = () => {}) {
  return { url: "http://127.0.0.1:1/v1/deployment/evaluate", token: "local-token",
    intent, profile: "human_first", context: {},
    trustedReceiptFingerprints: ["a".repeat(64)], fetchImpl, render };
}

test("public host gate times out a fetch that ignores abort and never renders", async () => {
  let signal;
  let renders = 0;
  const result = await evaluateLockedHttpAndRender({
    ...options(async (_url, init) => { signal = init.signal; return new Promise(() => {}); },
      () => { renders += 1; }), timeoutMs: 30
  });
  assert.deepEqual([result.status, result.reason, renders, signal.aborted],
    ["blocked", "evaluation_timeout", 0, true]);
});

test("public host gate times out an incomplete response body", async () => {
  let renders = 0;
  const incomplete = new ReadableStream({ start(controller) {
    controller.enqueue(new TextEncoder().encode('{"protocol":'));
  } });
  const result = await evaluateLockedHttpAndRender({
    ...options(async () => new Response(incomplete, { status: 200 }),
      () => { renders += 1; }), timeoutMs: 30
  });
  assert.deepEqual([result.status, result.reason, renders], ["blocked", "evaluation_timeout", 0]);
});

test("public host gate bounds advertised and streamed response bytes", async () => {
  let renders = 0;
  const render = () => { renders += 1; };
  const advertised = await evaluateLockedHttpAndRender({
    ...options(async () => new Response("{}", { status: 200,
      headers: { "content-length": "9999" } }), render), maxResponseBytes: 64
  });
  const streamed = await evaluateLockedHttpAndRender({
    ...options(async () => new Response("x".repeat(128), { status: 200 }), render),
    maxResponseBytes: 64
  });
  assert.deepEqual([advertised.reason, streamed.reason, renders],
    ["response_too_large", "response_too_large", 0]);
});

test("public host gate rejects HTTP failure without reading its body", async () => {
  let reads = 0;
  const result = await evaluateLockedHttpAndRender(options(async () => ({ status: 503,
    text: async () => { reads += 1; throw new Error("should not parse"); }
  })));
  assert.deepEqual([result.status, result.reason, reads], ["blocked", "http_evaluation_unavailable", 0]);
});

test("mutating caller trust configuration during fetch cannot authorize a different signer", async () => {
  const trusted = generateKeyPairSync("ed25519");
  const foreign = generateKeyPairSync("ed25519");
  const fingerprint = key => createHash("sha256")
    .update(key.export({ type: "spki", format: "der" })).digest("hex");
  const pins = [fingerprint(trusted.publicKey)];
  let renders = 0;
  const result = await evaluateLockedHttpAndRender({
    ...options(async (_url, init) => {
      pins[0] = fingerprint(foreign.publicKey);
      const { intent: submitted, request_nonce } = JSON.parse(init.body);
      const receipt = signExecutionReceipt(executeAccountableIntent(submitted, {
        profile: "human_first", context: {}, request_nonce,
        timestamp: "2030-01-01T00:00:00.000Z"
      }), foreign.privateKey.export({ type: "pkcs8", format: "pem" }), { signer: "foreign" });
      return new Response(JSON.stringify({ protocol: "aml-http-deployment-evaluation/1",
        policy_source: "server", mode: "enforce", failure_mode: "closed",
        evaluation_error: null, aml_allowed: true, effective_allowed: true,
        would_suppress: false, receipt }), { status: 200 });
    }, () => { renders += 1; }), trustedReceiptFingerprints: pins
  });
  assert.deepEqual([result.status, result.reason, renders], ["blocked", "receipt_untrusted", 0]);
});

test("network deadline ends before a verified host render callback runs", async () => {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const pem = privateKey.export({ type: "pkcs8", format: "pem" });
  const fingerprint = createHash("sha256")
    .update(publicKey.export({ type: "spki", format: "der" })).digest("hex");
  let renders = 0;
  const result = await evaluateLockedHttpAndRender({
    ...options(async (_url, init) => {
      const { intent: submitted, request_nonce } = JSON.parse(init.body);
      const receipt = signExecutionReceipt(executeAccountableIntent(submitted, {
        profile: "human_first", context: {}, request_nonce,
        timestamp: "2030-01-01T00:00:00.000Z"
      }), pem, { signer: "test-host" });
      return new Response(JSON.stringify({ protocol: "aml-http-deployment-evaluation/1",
        policy_source: "server", mode: "enforce", failure_mode: "closed",
        evaluation_error: null, aml_allowed: true, effective_allowed: true,
        would_suppress: false, receipt }), { status: 200 });
    }, async () => {
      await new Promise(resolve => setTimeout(resolve, 330));
      renders += 1;
    }),
    trustedReceiptFingerprints: [fingerprint], timeoutMs: 250
  });
  assert.deepEqual([result.status, result.reason, renders], ["rendered", "verified_allow", 1]);
});

test("host gate blocks signatures mislabeled as Ed25519 even when their key is pinned", async () => {
  for (const [type, keyOptions] of [["rsa", { modulusLength: 2048 }], ["ec", { namedCurve: "prime256v1" }]]) {
    const { privateKey, publicKey } = generateKeyPairSync(type, keyOptions);
    const fingerprint = createHash("sha256")
      .update(publicKey.export({ type: "spki", format: "der" })).digest("hex");
    let renders = 0;
    const result = await evaluateLockedHttpAndRender({
      ...options(async (_url, init) => {
        const { intent: submitted, request_nonce } = JSON.parse(init.body);
        const receipt = executeAccountableIntent(submitted, { profile: "human_first", context: {},
          request_nonce, timestamp: "2030-01-01T00:00:00.000Z" });
        const signedAt = "2030-01-01T01:00:00.000Z";
        // The sorted v1.1 material is validly signed by this RSA/EC key, but
        // its attestation falsely declares the Ed25519 algorithm.
        const material = JSON.stringify({ algorithm: "Ed25519", protocol: "ĀML Execution Receipt Attestation",
          receipt_sha256: receipt.receipt_sha256, signed_at: signedAt, signer: "synthetic", version: "1.1" });
        const bytes = Buffer.from(material);
        const signature = sign(null, bytes, privateKey);
        assert.equal(verify(null, bytes, publicKey, signature), true);
        receipt.signature = { protocol: "ĀML Execution Receipt Attestation", version: "1.1",
          algorithm: "Ed25519", signer: "synthetic", signed_at: signedAt,
          public_key_pem: publicKey.export({ type: "spki", format: "pem" }).toString(),
          public_key_sha256: fingerprint, signature_base64: signature.toString("base64") };
        return new Response(JSON.stringify({ protocol: "aml-http-deployment-evaluation/1",
          policy_source: "server", mode: "enforce", failure_mode: "closed",
          evaluation_error: null, aml_allowed: true, effective_allowed: true,
          would_suppress: false, receipt }), { status: 200 });
      }, () => { renders += 1; }), trustedReceiptFingerprints: [fingerprint]
    });
    assert.deepEqual([result.status, result.reason, renders], ["blocked", "receipt_invalid", 0]);
  }
});

test("host gate blocks alternate base64 spelling of an otherwise valid signature", async () => {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const fingerprint = createHash("sha256")
    .update(publicKey.export({ type: "spki", format: "der" })).digest("hex");
  let renders = 0;
  const result = await evaluateLockedHttpAndRender({
    ...options(async (_url, init) => {
      const { intent: submitted, request_nonce } = JSON.parse(init.body);
      const receipt = signExecutionReceipt(executeAccountableIntent(submitted, {
        profile: "human_first", context: {}, request_nonce,
        timestamp: "2030-01-01T00:00:00.000Z"
      }), privateKey.export({ type: "pkcs8", format: "pem" }), { signer: "synthetic" });
      const original = receipt.signature.signature_base64;
      receipt.signature.signature_base64 += "!!!!";
      assert.deepEqual(Buffer.from(receipt.signature.signature_base64, "base64"), Buffer.from(original, "base64"));
      return new Response(JSON.stringify({ protocol: "aml-http-deployment-evaluation/1",
        policy_source: "server", mode: "enforce", failure_mode: "closed",
        evaluation_error: null, aml_allowed: true, effective_allowed: true,
        would_suppress: false, receipt }), { status: 200 });
    }, () => { renders += 1; }), trustedReceiptFingerprints: [fingerprint]
  });
  assert.deepEqual([result.status, result.reason, renders], ["blocked", "receipt_invalid", 0]);
});
