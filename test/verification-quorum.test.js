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
  assert.equal(verifyVerificationQuorum(quorum).threshold_met, true);
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

test('verification quorum rejects truthy non-boolean verdicts', () => {
  const malformed = report('python-reference');
  malformed.valid = 'false';
  assert.throws(() => createVerificationQuorum([
    report('browser-reference'), malformed
  ], { threshold: 2 }), /AML_QUORUM_REPORT_VERDICT_INVALID/);
});

test('unsigned quorum keeps a detached JSON copy of the reports it counted', () => {
  const original = report('browser-reference');
  const quorum = createVerificationQuorum([original], { threshold: 2 });
  original.valid = false;
  original.checks.bundle_integrity = false;
  assert.equal(quorum.reports[0].valid, true);
  assert.equal(quorum.reports[0].checks.bundle_integrity, true);
  const result = verifyVerificationQuorum(quorum);
  assert.equal(result.valid, true);
  assert.equal(result.threshold_met, false);
});

test('unsigned quorum rejects rewritten envelope claims even if its counts still agree', () => {
  const quorum = createVerificationQuorum([
    report('browser-reference'), report('python-reference')
  ], { threshold: 2 });
  const edits = [
    saved => { saved.prototype = false; },
    saved => { saved.claim_boundary = 'Independently certified.'; },
    saved => { saved.unreviewed_claim = true; },
    saved => { saved.summary.unreviewed_count = 2; },
    saved => { saved.summary.unanimous = false; }
  ];
  for (const edit of edits) {
    const saved = structuredClone(quorum);
    edit(saved);
    const result = verifyVerificationQuorum(saved);
    assert.equal(result.valid, false);
    assert.equal(result.threshold_met, false);
  }
  const summaryEdit = structuredClone(quorum);
  summaryEdit.summary.unanimous = false;
  assert.equal(verifyVerificationQuorum(summaryEdit).reason, 'AML_QUORUM_SUMMARY_MISMATCH');
});

test('unsigned quorum refuses live fields excluded from saved JSON', () => {
  const input = report('browser-reference');
  Object.defineProperty(input, 'hidden_claim', { value: true });
  assert.throws(() => createVerificationQuorum([input]), /AML_CANONICAL_JSON_NON_JSON_OBJECT/);
  const saved = createVerificationQuorum([report('browser-reference')], { threshold: 1 });
  Object.defineProperty(saved, 'hidden_claim', { value: true });
  assert.deepEqual(verifyVerificationQuorum(saved), {
    valid: false, reason: 'AML_CANONICAL_JSON_NON_JSON_OBJECT', threshold_met: false
  });
});

test('unsigned report substitution is still structurally consistent without an external anchor', () => {
  const saved = createVerificationQuorum([report('browser-reference')], { threshold: 1 });
  saved.reports[0].checks.bundle_integrity = false;
  assert.equal(verifyVerificationQuorum(saved).valid, true);
});

test('unsigned quorum follows the published 64-report bound and rejects unsafe thresholds', () => {
  const reports = Array.from({ length: 65 }, (_, index) => report(`verifier-${index}`));
  assert.throws(() => createVerificationQuorum(reports), /AML_QUORUM_TOO_MANY_REPORTS/);
  assert.throws(() => createVerificationQuorum([reports[0]], {
    threshold: Number.MAX_SAFE_INTEGER + 1
  }), /AML_QUORUM_THRESHOLD_INVALID/);
});
