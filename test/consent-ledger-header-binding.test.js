import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";

import {
  canonicalJSONStringify,
  createConsentLedger,
  grantConsent,
  revokeConsent,
  verifyConsentLedger,
  resolveConsent
} from "../index.js";

function sha256Canonical(value) {
  return crypto.createHash("sha256").update(canonicalJSONStringify(value)).digest("hex");
}

test("consent ledger v1.1 binds subject and creation time into first event link", () => {
  const ledger = createConsentLedger({
    subject_id: "user:alpha",
    timestamp: "2026-09-09T05:00:00.000Z"
  });
  grantConsent(ledger, "notifications", { timestamp: "2026-09-09T05:01:00.000Z" });

  const verified = verifyConsentLedger(ledger);
  assert.equal(ledger.version, "1.1");
  assert.equal(verified.verified, true);
  assert.equal(verified.header_bound, true);
  assert.equal(verified.legacy_integrity_only, false);
  assert.equal(ledger.events[0].previous_hash, ledger.header_hash);

  const relabeled = structuredClone(ledger);
  relabeled.subject_id = "user:beta";
  assert.equal(verifyConsentLedger(relabeled).verified, false);

  const redated = structuredClone(ledger);
  redated.created_at = "2026-09-09T04:00:00.000Z";
  assert.equal(verifyConsentLedger(redated).verified, false);
});

test("unknown hash-valid consent action cannot become an implicit grant", () => {
  const ledger = createConsentLedger({
    subject_id: "user:alpha",
    timestamp: "2026-09-09T05:00:00.000Z"
  });
  const core = {
    sequence: 0,
    timestamp: "2026-09-09T05:01:00.000Z",
    action: "observe",
    scope: "notifications",
    expires_at: null,
    reason: null,
    previous_hash: ledger.header_hash
  };
  ledger.events.push({ ...core, event_hash: sha256Canonical(core) });

  const verified = verifyConsentLedger(ledger);
  assert.equal(verified.verified, false);
  assert.equal(verified.checks[0].action_valid, false);
  assert.equal(resolveConsent(ledger, "notifications", { at: "2026-09-09T05:02:00.000Z" }).granted, false);
});

test("consent verification fails closed on malformed event containers", () => {
  const ledger = createConsentLedger({ timestamp: "2026-09-09T05:00:00.000Z" });
  ledger.events = {};
  assert.equal(verifyConsentLedger(ledger).verified, false);

  const withNull = createConsentLedger({ timestamp: "2026-09-09T05:00:00.000Z" });
  withNull.events.push(null);
  const result = verifyConsentLedger(withNull);
  assert.equal(result.verified, false);
  assert.equal(result.checks[0].structure_valid, false);
});

test("legacy v1.0 hashes remain verifiable but are explicitly not header-bound", () => {
  const ledger = createConsentLedger({
    subject_id: "legacy:alpha",
    timestamp: "2026-09-09T05:00:00.000Z"
  });
  ledger.version = "1.0";
  delete ledger.header_hash;
  grantConsent(ledger, "analytics", { timestamp: "2026-09-09T05:01:00.000Z" });

  const verified = verifyConsentLedger(ledger);
  assert.equal(verified.verified, true);
  assert.equal(verified.header_bound, false);
  assert.equal(verified.legacy_integrity_only, true);

  const relabeled = structuredClone(ledger);
  relabeled.subject_id = "legacy:beta";
  const legacyRelabeled = verifyConsentLedger(relabeled);
  assert.equal(legacyRelabeled.verified, true);
  assert.equal(legacyRelabeled.header_bound, false);
  assert.equal(legacyRelabeled.legacy_integrity_only, true);
});

test("normal grant, expiry, and revocation semantics remain intact", () => {
  const ledger = createConsentLedger({
    subject_id: "user:alpha",
    timestamp: "2026-09-09T05:00:00.000Z"
  });
  grantConsent(ledger, "analytics", {
    timestamp: "2026-09-09T05:01:00.000Z",
    expires_at: "2026-09-09T06:00:00.000Z"
  });
  assert.equal(resolveConsent(ledger, "analytics", { at: "2026-09-09T05:30:00.000Z" }).granted, true);
  assert.equal(resolveConsent(ledger, "analytics", { at: "2026-09-09T06:00:00.000Z" }).granted, false);

  revokeConsent(ledger, "analytics", { timestamp: "2026-09-09T05:40:00.000Z" });
  assert.equal(verifyConsentLedger(ledger).verified, true);
  assert.equal(resolveConsent(ledger, "analytics", { at: "2026-09-09T05:50:00.000Z" }).granted, false);
});

test("v1.1 issuance rejects unsupported reason values before hashing", () => {
  const ledger = createConsentLedger({ timestamp: "2026-09-09T05:00:00.000Z" });
  assert.throws(
    () => grantConsent(ledger, "analytics", { reason: new Date(), timestamp: "2026-09-09T05:01:00.000Z" }),
    /reason must be a string or null/
  );
});
