import test from "node:test";
import assert from "node:assert/strict";

import {
  createPolicyPassport,
  verifyPolicyPassport,
  passportContext
} from "../index.js";

test("expired policy passports fail verification by default", () => {
  const passport = createPolicyPassport({
    subject: "user:alpha",
    profile: "human_first",
    issued_at: "2000-01-01T00:00:00.000Z",
    expires_at: "2000-01-02T00:00:00.000Z"
  });
  const result = verifyPolicyPassport(passport);
  assert.equal(result.valid, false);
  assert.equal(result.reason, "expired");
});

test("passportContext cannot inject an expired passport", () => {
  const passport = createPolicyPassport({
    subject: "user:alpha",
    profile: "human_first",
    preferences: { calm_mode: true },
    issued_at: "2000-01-01T00:00:00.000Z",
    expires_at: "2000-01-02T00:00:00.000Z"
  });
  assert.deepEqual(passportContext(passport), { policy_passport_valid: false });
  assert.deepEqual(passportContext(passport, { now: null }), { policy_passport_valid: false });
});

test("future-issued policy passports are not yet valid", () => {
  const passport = createPolicyPassport({
    profile: "human_first",
    issued_at: "2999-01-01T00:00:00.000Z",
    expires_at: "2999-01-02T00:00:00.000Z"
  });
  const result = verifyPolicyPassport(passport);
  assert.equal(result.valid, false);
  assert.equal(result.reason, "not_yet_valid");
});

test("passport issuance rejects inverted time windows", () => {
  assert.throws(
    () => createPolicyPassport({
      profile: "human_first",
      issued_at: "2026-09-09T06:00:00.000Z",
      expires_at: "2026-09-09T05:00:00.000Z"
    }),
    /expires_at must be after issued_at/
  );
});

test("explicit deterministic verification time remains supported", () => {
  const passport = createPolicyPassport({
    profile: "human_first",
    issued_at: "2026-09-09T05:00:00.000Z",
    expires_at: "2026-09-09T07:00:00.000Z"
  });
  const valid = verifyPolicyPassport(passport, { now: "2026-09-09T06:00:00.000Z" });
  assert.equal(valid.valid, true);
  assert.equal(valid.temporal_validation, "enforced");
  assert.equal(passportContext(passport, { now: "2026-09-09T06:00:00.000Z" }).policy_passport_valid, true);
});

test("integrity-only verification is explicit and never accepted by passportContext", () => {
  const passport = createPolicyPassport({
    profile: "human_first",
    issued_at: "2000-01-01T00:00:00.000Z",
    expires_at: "2000-01-02T00:00:00.000Z"
  });
  const integrityOnly = verifyPolicyPassport(passport, { now: null });
  assert.equal(integrityOnly.valid, true);
  assert.equal(integrityOnly.temporal_validation, "skipped_explicitly");
  assert.equal(passportContext(passport, { now: null }).policy_passport_valid, false);
});

test("malformed passport input fails closed rather than throwing", () => {
  assert.deepEqual(verifyPolicyPassport(null), { valid: false, reason: "invalid_type" });
  const cyclic = { type: "aml-policy-passport/1" };
  cyclic.self = cyclic;
  assert.deepEqual(verifyPolicyPassport(cyclic), { valid: false, reason: "verification_error" });
});
