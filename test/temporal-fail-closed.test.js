import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";

import {
  createPolicyPassport,
  verifyPolicyPassport,
  createConsentLedger,
  grantConsent,
  resolveConsent,
  verifyConsentLedger,
  createReplayGuard,
  acceptWireEnvelope
} from "../index.js";

function stable(value) {
  if (Array.isArray(value)) return value.map(stable);
  if (value && typeof value === "object") {
    return Object.fromEntries(Object.keys(value).sort().map(key => [key, stable(value[key])]));
  }
  return value;
}

function digest(value) {
  return crypto.createHash("sha256").update(JSON.stringify(stable(value))).digest("hex");
}

function stableStringify(value) {
  if (Array.isArray(value)) return `[${value.map(stableStringify).join(",")}]`;
  if (value && typeof value === "object") {
    return `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${stableStringify(value[key])}`).join(",")}}`;
  }
  return JSON.stringify(value);
}

function sha256(value) {
  return crypto.createHash("sha256").update(stableStringify(value)).digest("hex");
}

test("policy passport creation rejects malformed temporal metadata", () => {
  assert.throws(() => createPolicyPassport({
    profile: "calm_default",
    issued_at: "not-a-time"
  }), /issued_at must be a valid timestamp/);

  assert.throws(() => createPolicyPassport({
    profile: "calm_default",
    expires_at: "not-a-time"
  }), /expires_at must be a valid timestamp/);
});

test("policy passport verification rejects a hash-consistent malformed expiry", () => {
  const body = {
    type: "aml-policy-passport/1",
    subject: "subject-1",
    profile: "calm_default",
    preferences: {},
    issued_at: "2030-01-01T00:00:00.000Z",
    expires_at: "not-a-time"
  };
  const passport = { ...body, passport_hash: digest(body) };

  assert.deepEqual(verifyPolicyPassport(passport, { now: "2030-01-02T00:00:00.000Z" }), {
    valid: false,
    reason: "invalid_expires_at"
  });
});

test("policy passport verification rejects an invalid evaluation time", () => {
  const passport = createPolicyPassport({
    profile: "calm_default",
    issued_at: "2030-01-01T00:00:00.000Z",
    expires_at: "2030-02-01T00:00:00.000Z"
  });

  assert.deepEqual(verifyPolicyPassport(passport, { now: "not-a-time" }), {
    valid: false,
    reason: "invalid_now"
  });
});

test("ordinary policy passport expiry behavior is preserved", () => {
  const passport = createPolicyPassport({
    profile: "calm_default",
    issued_at: "2030-01-01T00:00:00.000Z",
    expires_at: "2030-02-01T00:00:00.000Z"
  });

  assert.equal(verifyPolicyPassport(passport, { now: "2030-01-15T00:00:00.000Z" }).valid, true);
  assert.equal(verifyPolicyPassport(passport, { now: "2030-02-01T00:00:00.000Z" }).reason, "expired");
});

test("consent ledger refuses malformed event timestamps and expiries at ingress", () => {
  assert.throws(() => createConsentLedger({ timestamp: "not-a-time" }), /timestamp must be a valid timestamp/);

  const ledger = createConsentLedger({ timestamp: "2030-01-01T00:00:00.000Z" });
  assert.throws(() => grantConsent(ledger, "personalization", {
    timestamp: "not-a-time"
  }), /timestamp must be a valid timestamp/);
  assert.throws(() => grantConsent(ledger, "personalization", {
    timestamp: "2030-01-01T00:00:00.000Z",
    expires_at: "not-a-time"
  }), /expires_at must be a valid timestamp/);
  assert.equal(ledger.events.length, 0);
});

test("consent verification rejects hash-consistent malformed temporal events", () => {
  const ledger = createConsentLedger({ timestamp: "2030-01-01T00:00:00.000Z" });
  const core = {
    sequence: 0,
    timestamp: "2030-01-01T00:00:01.000Z",
    action: "grant",
    scope: "personalization",
    expires_at: "not-a-time",
    reason: null,
    previous_hash: null
  };
  ledger.events.push({ ...core, event_hash: sha256(core) });

  const verification = verifyConsentLedger(ledger);
  assert.equal(verification.verified, false);
  assert.equal(verification.checks[0].hash_valid, true);
  assert.equal(verification.checks[0].expires_at_valid, false);
  assert.equal(resolveConsent(ledger, "personalization", { at: "2030-01-02T00:00:00.000Z" }).granted, false);
});

test("consent resolution fails closed on invalid evaluation time", () => {
  const ledger = createConsentLedger({ timestamp: "2030-01-01T00:00:00.000Z" });
  grantConsent(ledger, "personalization", {
    timestamp: "2030-01-01T00:00:01.000Z",
    expires_at: "2030-02-01T00:00:00.000Z"
  });

  const result = resolveConsent(ledger, "personalization", { at: "not-a-time" });
  assert.equal(result.granted, false);
  assert.equal(result.reason, "invalid evaluation timestamp");
});

test("replay guard rejects malformed expiry without poisoning replay state", () => {
  const guard = createReplayGuard();
  const malformed = {
    session_id: "session-1",
    nonce: "nonce-1",
    issued_at: "2030-01-01T00:00:00.000Z",
    expires_at: "not-a-time"
  };

  const rejected = acceptWireEnvelope(guard, malformed, { now: "2030-01-01T00:00:01.000Z" });
  assert.equal(rejected.accepted, false);
  assert.equal(rejected.reason, "invalid_expires_at");
  assert.deepEqual(rejected.guard.seen, {});

  const corrected = { ...malformed, expires_at: "2030-01-01T00:01:00.000Z" };
  const accepted = acceptWireEnvelope(rejected.guard, corrected, { now: "2030-01-01T00:00:01.000Z" });
  assert.equal(accepted.accepted, true);
});

test("replay guard rejects invalid evaluation time without poisoning state", () => {
  const guard = createReplayGuard();
  const envelope = {
    session_id: "session-2",
    nonce: "nonce-2",
    expires_at: "2030-01-01T00:01:00.000Z"
  };

  const rejected = acceptWireEnvelope(guard, envelope, { now: "not-a-time" });
  assert.equal(rejected.accepted, false);
  assert.equal(rejected.reason, "invalid_now");
  assert.deepEqual(rejected.guard.seen, {});
});
