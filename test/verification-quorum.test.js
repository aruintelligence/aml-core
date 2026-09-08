import test from 'node:test';
import assert from 'node:assert/strict';
import { createVerificationQuorum, verifyVerificationQuorum } from '../docs/aml-verification-quorum.js';

function report(verifier, valid = true, reason = 'AML_WITNESS_BUNDLE_VALID') {
  return {
    schema: 'aml-verification-report/1',
    prototype: true,
    verifier,
    artifact_type: 'aml-witness-bundle/1',
    valid,
    reason,
    checked_at: '2030-01-01T00:05:00.000Z',
    artifact_hash: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
    session_key_fingerprint: null,
    challenge_expires_at: '2030-01-01T00:10:00.000Z',
    checks: { bundle_integrity: valid },
    notes: []
  };
}

test('verification quorum counts distinct reports over one artifact', () => {
  const quorum = createVerificationQuorum([
    report('browser-reference'),
    report('python-reference'),
    report('http-reference')
  ], { threshold: 2 });
  assert.equal(quorum.summary.distinct_verifiers, 3);
  assert.equal(quorum.summary.valid_reports, 3);
  assert.equal(quorum.summary.threshold_met, true);
  assert.equal(quorum.summary.unanimous, true);
  assert.equal(verifyVerificationQuorum(quorum).valid, true);
});

test('verification quorum preserves disagreement instead of flattening it', () => {
  const quorum = createVerificationQuorum([
    report('browser-reference'),
    report('python-reference', false, 'AML_SESSION_SIGNATURE_INVALID'),
    report('http-reference')
  ], { threshold: 2 });
  assert.equal(quorum.summary.threshold_met, true);
  assert.equal(quorum.summary.unanimous, false);
  assert.deepEqual(quorum.summary.disagreement_reasons, ['AML_SESSION_SIGNATURE_INVALID']);
});

test('verification quorum rejects duplicate verifier IDs', () => {
  assert.throws(() => createVerificationQuorum([
    report('same-verifier'),
    report('same-verifier')
  ]), /AML_QUORUM_DUPLICATE_VERIFIER/);
});

test('verification quorum rejects reports for different artifacts', () => {
  const other = report('python-reference');
  other.artifact_hash = 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb';
  assert.throws(() => createVerificationQuorum([
    report('browser-reference'), other
  ]), /AML_QUORUM_ARTIFACT_HASH_MISMATCH/);
});
