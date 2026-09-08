import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import { signCapabilityToken, verifyCapabilityToken } from "../index.js";

function privatePem() {
  return crypto.generateKeyPairSync("ed25519").privateKey.export({ type: "pkcs8", format: "pem" }).toString();
}

test("bounded capability token verifies audience, capability, and signature", () => {
  const token = signCapabilityToken({
    issuer: "root",
    subject: "agent-7",
    audience: "interface-firewall",
    capabilities: ["render-proposal", "request-policy-evaluation"],
    issued_at: "2026-01-01T00:00:00.000Z",
    expires_at: "2026-01-01T01:00:00.000Z",
    nonce: "abc"
  }, privatePem());

  assert.equal(verifyCapabilityToken(token, {
    now: "2026-01-01T00:30:00.000Z",
    audience: "interface-firewall",
    requiredCapability: "render-proposal"
  }).valid, true);
});

test("capability token rejects mutation, wrong audience, and expiry", () => {
  const token = signCapabilityToken({
    issuer: "root",
    audience: "interface-firewall",
    capabilities: ["render-proposal"],
    expires_at: "2026-01-01T01:00:00.000Z"
  }, privatePem());

  const mutated = structuredClone(token);
  mutated.capabilities.push("admin");
  assert.equal(verifyCapabilityToken(mutated).valid, false);
  assert.equal(verifyCapabilityToken(token, { audience: "other-system" }).reason, "audience_mismatch");
  assert.equal(verifyCapabilityToken(token, { now: "2026-01-01T01:00:00.000Z" }).reason, "expired");
});
