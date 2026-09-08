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
