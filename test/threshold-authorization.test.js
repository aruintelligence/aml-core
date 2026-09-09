import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import { createThresholdAuthorization, verifyThresholdAuthorization } from "../index.js";

function privatePem() {
  return crypto.generateKeyPairSync("ed25519").privateKey.export({ type: "pkcs8", format: "pem" }).toString();
}

test("threshold authorization accepts distinct valid signers", () => {
  const authorization = createThresholdAuthorization(
    { action: "publish-policy", policy_hash: "abc123" },
    [privatePem(), privatePem(), privatePem()],
    { threshold: 2 }
  );
  const result = verifyThresholdAuthorization(authorization);
  assert.equal(result.valid, true);
  assert.equal(result.valid_signatures, 3);
  assert.equal(result.threshold_bound, true);
});

test("threshold authorization rejects tampered payloads", () => {
  const authorization = createThresholdAuthorization(
    { action: "publish-policy", policy_hash: "abc123" },
    [privatePem(), privatePem()],
    { threshold: 2 }
  );
  const tampered = structuredClone(authorization);
  tampered.payload.policy_hash = "attacker";
  const result = verifyThresholdAuthorization(tampered);
  assert.equal(result.valid, false);
  assert.equal(result.reason, "threshold_not_met");
});

test("threshold authorization rejects a lowered quorum", () => {
  const authorization = createThresholdAuthorization(
    { action: "publish-policy", policy_hash: "abc123" },
    [privatePem(), privatePem(), privatePem()],
    { threshold: 2 }
  );

  const tampered = structuredClone(authorization);
  tampered.threshold = 1;
  const result = verifyThresholdAuthorization(tampered);

  assert.equal(result.valid, false);
  assert.equal(result.reason, "threshold_not_met");
  assert.equal(result.valid_signatures, 0);
  assert.equal(result.threshold_bound, true);
});

test("legacy threshold authorizations fail closed because quorum was not signed", () => {
  const legacy = createThresholdAuthorization(
    { action: "publish-policy", policy_hash: "abc123" },
    [privatePem(), privatePem()],
    { threshold: 2 }
  );
  delete legacy.version;

  const result = verifyThresholdAuthorization(legacy);
  assert.equal(result.valid, false);
  assert.equal(result.reason, "legacy_threshold_unbound");
  assert.equal(result.threshold_bound, false);
});

test("threshold verifier fails closed on a non-array signatures field", () => {
  const authorization = createThresholdAuthorization(
    { action: "publish-policy", policy_hash: "abc123" },
    [privatePem()],
    { threshold: 1 }
  );
  authorization.signatures = { attacker: "not-an-array" };

  assert.doesNotThrow(() => verifyThresholdAuthorization(authorization));
  const result = verifyThresholdAuthorization(authorization);
  assert.equal(result.valid, false);
  assert.equal(result.reason, "invalid_signatures");
  assert.equal(result.valid_signatures, 0);
});

test("threshold verifier fails closed when canonical payload material is invalid", () => {
  const authorization = {
    type: "aml-threshold-authorization/1",
    version: "1.1",
    threshold: 1,
    payload: { impossible_over_json: 1n },
    signatures: []
  };

  assert.doesNotThrow(() => verifyThresholdAuthorization(authorization));
  const result = verifyThresholdAuthorization(authorization);
  assert.equal(result.valid, false);
  assert.equal(result.reason, "invalid_payload");
  assert.equal(result.valid_signatures, 0);
});

test("threshold verifier tolerates malformed individual signer entries", () => {
  const authorization = createThresholdAuthorization(
    { action: "publish-policy", policy_hash: "abc123" },
    [privatePem()],
    { threshold: 1 }
  );
  authorization.signatures = [null, 42, { public_key_pem: "not-a-key" }];

  assert.doesNotThrow(() => verifyThresholdAuthorization(authorization));
  const result = verifyThresholdAuthorization(authorization);
  assert.equal(result.valid, false);
  assert.equal(result.reason, "threshold_not_met");
  assert.equal(result.valid_signatures, 0);
});
