import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import { signBrandAuthorization } from "../runtime/brandAuthorization.js";
import { verifyOfficialBrandAuthorization, verifyBrandTrustRegistry } from "../runtime/brandTrust.js";

function issueCredential() {
  const { privateKey } = crypto.generateKeyPairSync("ed25519");
  const credential = signBrandAuthorization({
    grantee: "Example Integrator LLC",
    marks: ["ĀML Compatible™"],
    uses: ["official-compatible-badge"],
    authorization_id: "trust-test-1"
  }, privateKey.export({ type: "pkcs8", format: "pem" }), { issuer: "ĀRU Intelligence Inc." });
  return { credential };
}

test("an unprovisioned trust registry does not make a self-signed credential official", () => {
  const { credential } = issueCredential();
  const registry = {
    type: "aml-brand-trust-roots/1",
    owner: "ĀRU Intelligence Inc.",
    active_keys: [],
    revoked_keys: []
  };
  const result = verifyOfficialBrandAuthorization(credential, registry);
  assert.equal(result.valid, false);
  assert.equal(result.official, false);
  assert.equal(result.reason, "untrusted_signing_key");
});

test("a credential becomes official only when its signer fingerprint is in the trusted registry", () => {
  const { credential } = issueCredential();
  const registry = {
    type: "aml-brand-trust-roots/1",
    owner: "ĀRU Intelligence Inc.",
    active_keys: [{
      key_id: "test-key",
      public_key_sha256: credential.public_key_sha256,
      purpose: "brand-authorization-test"
    }],
    revoked_keys: []
  };
  assert.equal(verifyBrandTrustRegistry(registry).valid, true);
  const result = verifyOfficialBrandAuthorization(credential, registry);
  assert.equal(result.valid, true);
  assert.equal(result.official, true);
  assert.equal(result.trust_root.key_id, "test-key");
});

test("a revoked signer cannot produce an official credential", () => {
  const { credential } = issueCredential();
  const registry = {
    type: "aml-brand-trust-roots/1",
    owner: "ĀRU Intelligence Inc.",
    active_keys: [],
    revoked_keys: [{
      key_id: "revoked-test-key",
      public_key_sha256: credential.public_key_sha256,
      revoked_at: "2026-09-08T00:00:00.000Z"
    }]
  };
  const result = verifyOfficialBrandAuthorization(credential, registry);
  assert.equal(result.valid, false);
  assert.equal(result.official, false);
  assert.equal(result.reason, "signing_key_revoked");
});
