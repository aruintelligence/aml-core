import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import { parseBrandTime } from "../runtime/brandTime.js";
import { signBrandAuthorization, verifyBrandAuthorization } from "../runtime/brandAuthorization.js";
import { verifyBrandTrustRegistry } from "../runtime/brandTrust.js";
import { acceptedBrandTimes, rejectedBrandTimes, impossibleBrandTime, timezoneFreeBrandTime } from "./fixtures/brand-times.js";

test("brand time parser rejects normalized dates and ambiguous local times", () => {
  assert.ok(Number.isFinite(Date.parse(impossibleBrandTime)), "regression requires a lenient native parser");
  for (const value of acceptedBrandTimes) assert.notEqual(parseBrandTime(value), null, value);
  for (const value of rejectedBrandTimes) assert.equal(parseBrandTime(value), null, value);
  assert.equal(parseBrandTime(acceptedBrandTimes[1]), parseBrandTime(acceptedBrandTimes[3]));
  assert.equal(parseBrandTime(acceptedBrandTimes[1]), parseBrandTime(acceptedBrandTimes[4]));
});

test("brand signer and verifier reject invalid issue, expiry, and as-of times", () => {
  const { privateKey } = crypto.generateKeyPairSync("ed25519");
  const pem = privateKey.export({ type: "pkcs8", format: "pem" });
  const request = { grantee: "Example Integrator LLC", marks: ["ĀML™"] };
  assert.throws(() => signBrandAuthorization({ ...request, issued_at: impossibleBrandTime }, pem), /invalid_issued_at/);
  assert.throws(() => signBrandAuthorization({ ...request, expires_at: timezoneFreeBrandTime }, pem), /invalid_expires_at/);
  const credential = signBrandAuthorization(request, pem);
  assert.equal(verifyBrandAuthorization({ ...credential, issued_at: impossibleBrandTime }).reason, "invalid_issued_at");
  assert.equal(verifyBrandAuthorization(credential, { now: timezoneFreeBrandTime }).reason, "invalid_now");
});

test("brand trust roots reject impossible and timezone-free validity windows", () => {
  const roots = {
    type: "aml-brand-trust-roots/1", owner: "ĀRU Intelligence Inc.", status: "active",
    active_keys: [{ public_key_sha256: "a".repeat(64), not_before: impossibleBrandTime }],
    revoked_keys: []
  };
  assert.equal(verifyBrandTrustRegistry(roots).reason, "invalid_active_key_window");
  roots.active_keys[0].not_before = timezoneFreeBrandTime;
  assert.equal(verifyBrandTrustRegistry(roots).reason, "invalid_active_key_window");
  roots.active_keys[0].not_before = acceptedBrandTimes[3];
  roots.active_keys[0].not_after = acceptedBrandTimes[1];
  assert.equal(verifyBrandTrustRegistry(roots).reason, "invalid_active_key_window");
});
