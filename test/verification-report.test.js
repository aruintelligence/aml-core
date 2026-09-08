import test from 'node:test';
import assert from 'node:assert/strict';

import { createVerificationReport, witnessVerificationReport } from '../docs/aml-verification-report.js';

test('verification report normalizes a successful witness result', () => {
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
  assert.equal(report.checks.bundle_integrity, true);
  assert.match(report.notes.join(' '), /does not prove identity/i);
});

test('verification report rejects incomplete constructor input', () => {
  assert.throws(() => createVerificationReport({ verifier: 'x' }), /AML_VERIFICATION_REPORT_INPUT_INVALID/);
});
