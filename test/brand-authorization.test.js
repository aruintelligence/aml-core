import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import { signBrandAuthorization, verifyBrandAuthorization } from "../runtime/brandAuthorization.js";
import { createRevocationRegistry, revokeArtifact } from "../runtime/revocationRegistry.js";

function keys() {
  return crypto.generateKeyPairSync("ed25519");
}

test("signed brand authorization verifies with exact scope", () => {
  const { privateKey } = keys();
  const credential = signBrandAuthorization({
    grantee: "Example Integrator LLC",
    marks: ["ĀML™", "ĀML Compatible™"],
    uses: ["official-compatible-badge", "integration-marketing"],
    issued_at: "2026-09-08T00:00:00.000Z",
    expires_at: "2027-09-08T00:00:00.000Z",
    authorization_id: "auth-example-1",
    agreement_reference: "agreement-2026-001"
  }, privateKey.export({ type: "pkcs8", format: "pem" }), { issuer: "ĀRU Intelligence Inc." });

  const verified = verifyBrandAuthorization(credential, {
    now: "2026-10-01T00:00:00.000Z",
    expected_issuer: "ĀRU Intelligence Inc."
  });

  assert.equal(verified.valid, true);
  assert.deepEqual(verified.marks, ["ĀML Compatible™", "ĀML™"].sort());
});

test("tampering invalidates a brand authorization", () => {
  const { privateKey } = keys();
  const credential = signBrandAuthorization({
    grantee: "Example Integrator LLC",
    marks: ["ĀML™"],
    uses: ["documentation-reference"]
  }, privateKey.export({ type: "pkcs8", format: "pem" }));

  const tampered = { ...credential, grantee: "Other Company" };
  assert.equal(verifyBrandAuthorization(tampered).valid, false);
});

test("expired authorization fails verification", () => {
  const { privateKey } = keys();
  const credential = signBrandAuthorization({
    grantee: "Example Integrator LLC",
    marks: ["ĀML™"],
    expires_at: "2026-09-01T00:00:00.000Z"
  }, privateKey.export({ type: "pkcs8", format: "pem" }));

  const verified = verifyBrandAuthorization(credential, { now: "2026-09-08T00:00:00.000Z" });
  assert.equal(verified.valid, false);
  assert.equal(verified.reason, "expired");
});

test("revoked authorization fails verification", () => {
  const { privateKey } = keys();
  const credential = signBrandAuthorization({
    grantee: "Example Integrator LLC",
    marks: ["ĀML™"]
  }, privateKey.export({ type: "pkcs8", format: "pem" }));

  let registry = createRevocationRegistry();
  registry = revokeArtifact(registry, credential.credential_hash, {
    reason: "authorization_terminated",
    revoked_at: "2026-09-08T00:00:00.000Z"
  });

  const verified = verifyBrandAuthorization(credential, { revocation_registry: registry });
  assert.equal(verified.valid, false);
  assert.equal(verified.reason, "revoked");
});
