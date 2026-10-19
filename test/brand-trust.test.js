import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import { signBrandAuthorization } from "../runtime/brandAuthorization.js";
import { verifyOfficialBrandAuthorization, verifyBrandTrustRegistry } from "../runtime/brandTrust.js";

function issueCredential(times = {}) {
  const { privateKey } = crypto.generateKeyPairSync("ed25519");
  const credential = signBrandAuthorization({
    grantee: "Example Integrator LLC",
    marks: ["ĀML Compatible™"],
    uses: ["official-compatible-badge"],
    authorization_id: "trust-test-1",
    ...times
  }, privateKey.export({ type: "pkcs8", format: "pem" }), { issuer: "ĀRU Intelligence Inc." });
  return { credential };
}

test("an unprovisioned trust registry does not make a self-signed credential official", () => {
  const { credential } = issueCredential();
  const registry = {
    type: "aml-brand-trust-roots/1",
    owner: "ĀRU Intelligence Inc.",
    status: "unprovisioned",
    active_keys: [],
    revoked_keys: []
  };
  const result = verifyOfficialBrandAuthorization(credential, registry);
  assert.equal(result.valid, false);
  assert.equal(result.official, false);
  assert.equal(result.reason, "trust_registry_inactive");
});

test("a credential becomes official only when its signer fingerprint is in the trusted registry", () => {
  const { credential } = issueCredential();
  const registry = {
    type: "aml-brand-trust-roots/1",
    owner: "ĀRU Intelligence Inc.",
    status: "active",
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
    status: "active",
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

test("official trust requires the credential and signer to be active at the same instant", () => {
  const { credential } = issueCredential({ issued_at: "2000-01-01T00:00:00Z", expires_at: "2100-01-01T00:00:00Z" });
  const registry = {
    type: "aml-brand-trust-roots/1",
    owner: "ĀRU Intelligence Inc.",
    status: "active",
    active_keys: [{ public_key_sha256: credential.public_key_sha256, not_before: "2020-01-01T00:00:00Z", not_after: "2021-01-01T00:00:00Z" }],
    revoked_keys: []
  };
  assert.equal(verifyOfficialBrandAuthorization(credential, registry).reason, "signing_key_expired");
  const historical = verifyOfficialBrandAuthorization(credential, registry, { now: "2020-06-01T00:00:00Z" });
  assert.equal(historical.official, true);
  assert.equal(historical.clock_source, "caller_supplied");
  assert.equal(verifyOfficialBrandAuthorization(credential, registry, { now: "2019-12-31T23:59:59Z" }).reason, "signing_key_not_yet_valid");
  assert.equal(verifyOfficialBrandAuthorization(credential, registry, { now: registry.active_keys[0].not_before }).official, true);
  assert.equal(verifyOfficialBrandAuthorization(credential, registry, { now: registry.active_keys[0].not_after }).reason, "signing_key_expired");
  registry.active_keys[0].not_before = "2100-01-01T00:00:00Z";
  registry.active_keys[0].not_after = null;
  assert.equal(verifyOfficialBrandAuthorization(credential, registry).reason, "signing_key_not_yet_valid");
});

test("malformed or inverted trust-root time windows fail closed", () => {
  const { credential } = issueCredential();
  const registry = {
    type: "aml-brand-trust-roots/1", owner: "ĀRU Intelligence Inc.",
    status: "active",
    active_keys: [{ public_key_sha256: credential.public_key_sha256, not_before: "not-a-date" }],
    revoked_keys: []
  };
  assert.equal(verifyBrandTrustRegistry(registry).reason, "invalid_active_key_window");
  assert.equal(verifyOfficialBrandAuthorization(credential, registry).reason, "invalid_trust_registry");
  registry.active_keys[0] = { public_key_sha256: credential.public_key_sha256, not_before: "2021-01-01T00:00:00Z", not_after: "2020-01-01T00:00:00Z" };
  assert.equal(verifyBrandTrustRegistry(registry).reason, "invalid_active_key_window");
});

test("a suspended or unprovisioned trust registry cannot confer official status", () => {
  const { credential } = issueCredential();
  const registry = {
    type: "aml-brand-trust-roots/1", owner: "ĀRU Intelligence Inc.", status: "suspended",
    active_keys: [{ public_key_sha256: credential.public_key_sha256 }], revoked_keys: []
  };
  assert.equal(verifyBrandTrustRegistry(registry).valid, true);
  assert.equal(verifyOfficialBrandAuthorization(credential, registry).reason, "trust_registry_inactive");
  registry.status = "unprovisioned";
  assert.equal(verifyOfficialBrandAuthorization(credential, registry).reason, "trust_registry_inactive");
  delete registry.status;
  assert.equal(verifyOfficialBrandAuthorization(credential, registry).registry_reason, "invalid_status");
});

test("an official issuer is bound to the registry owner even with a caller issuer override", () => {
  const { privateKey } = crypto.generateKeyPairSync("ed25519");
  const credential = signBrandAuthorization({
    grantee: "Example Integrator LLC", marks: ["ĀML™"]
  }, privateKey.export({ type: "pkcs8", format: "pem" }), { issuer: "Different Issuer" });
  const registry = {
    type: "aml-brand-trust-roots/1", owner: "ĀRU Intelligence Inc.", status: "active",
    active_keys: [{ public_key_sha256: credential.public_key_sha256 }], revoked_keys: []
  };
  const result = verifyOfficialBrandAuthorization(credential, registry, { expected_issuer: "Different Issuer" });
  assert.equal(result.official, false);
  assert.equal(result.reason, "issuer_mismatch");
});
