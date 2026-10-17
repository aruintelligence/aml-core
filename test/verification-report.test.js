import test from 'node:test';
import assert from 'node:assert/strict';

import { createVerificationReport, witnessVerificationReport } from '../docs/aml-verification-report.js';

test('verification report never infers passed steps from an overall verdict', () => {
  const bundle = {
    integrity: { value: 'a'.repeat(64) },
    attestation: { session_key_fingerprint: 'b'.repeat(64) },
    challenge: { expires_at: '2030-01-01T00:10:02.000Z' }
  };
  const report = witnessVerificationReport(bundle, { valid: true, reason: 'AML_WITNESS_BUNDLE_VALID' });
  assert.equal(report.schema, 'aml-verification-report/1');
  assert.equal(report.valid, true);
  assert.equal(report.artifact_type, 'aml-witness-bundle/1');
  assert.equal(report.artifact_hash, 'a'.repeat(64));
  assert.equal(report.session_key_fingerprint, 'b'.repeat(64));
  assert.equal(Object.values(report.checks).every(passed => passed === false), true);
  assert.match(report.notes.join(' '), /does not prove identity/i);
});

test('only explicit true steps are reported as passed', () => {
  const report = witnessVerificationReport({}, {
    valid: true,
    reason: 'AML_WITNESS_BUNDLE_VALID',
    checks: { bundle_integrity: true, receipt_integrity: 'true', challenge_binding: 1 }
  });
  assert.equal(report.checks.bundle_integrity, true);
  assert.equal(report.checks.receipt_integrity, false);
  assert.equal(report.checks.challenge_binding, false);
  assert.equal(report.checks.session_signature, false);
});

test('an incomplete observed snapshot cannot be mixed with live bundle fields', () => {
  assert.throws(() => witnessVerificationReport({ integrity: { value: 'a'.repeat(64) } }, {
    valid: true, inspected: { session_key_fingerprint: 'b'.repeat(64) }
  }), /AML_VERIFICATION_REPORT_INSPECTED_INVALID/);
});

test('verification report rejects incomplete constructor input', () => {
  assert.throws(() => createVerificationReport({ verifier: 'x' }), /AML_VERIFICATION_REPORT_INPUT_INVALID/);
});

test('verification report records a verifier-held challenge mismatch', () => {
  const report = witnessVerificationReport({ challenge: {} }, {
    valid: false, reason: 'AML_WITNESS_BUNDLE_CHALLENGE_MISMATCH'
  });
  assert.equal(report.valid, false);
  assert.equal(report.checks.challenge_binding, false);
});

test('verification report does not call an invalid challenge fresh', () => {
  for (const reason of [
    'AML_CHALLENGE_EXPIRED', 'AML_CHALLENGE_NOT_YET_VALID', 'AML_CHALLENGE_TIME_INVALID'
  ]) {
    const report = witnessVerificationReport({ challenge: {} }, { valid: false, reason });
    assert.equal(report.checks.challenge_freshness, false, reason);
  }
});

test('a failure reason alone never asserts that unrelated steps passed', () => {
  for (const reason of ['AML_SESSION_EVIDENCE_INVALID', 'AML_WITNESS_BUNDLE_HASH_MISMATCH']) {
    const report = witnessVerificationReport({}, { valid: false, reason });
    assert.equal(Object.values(report.checks).every((passed) => passed === false), true, reason);
  }
});

test('verification report does not mark malformed bundle integrity as passed', () => {
  for (const reason of [
    'AML_WITNESS_BUNDLE_UNSEALED',
    'AML_WITNESS_BUNDLE_CANONICALIZATION_UNSUPPORTED',
    'AML_WITNESS_BUNDLE_INTEGRITY_INVALID',
    'AML_CANONICAL_JSON_NON_JSON_OBJECT'
  ]) {
    const report = witnessVerificationReport({}, { valid: false, reason });
    assert.equal(report.checks.bundle_integrity, false, reason);
  }
});
