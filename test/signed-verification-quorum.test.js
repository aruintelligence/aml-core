import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { webcrypto } from 'node:crypto';

if (!globalThis.crypto) globalThis.crypto = webcrypto;
if (!globalThis.btoa) globalThis.btoa = (value) => Buffer.from(value, 'binary').toString('base64');
if (!globalThis.atob) globalThis.atob = (value) => Buffer.from(value, 'base64').toString('binary');

import {
  createVerifierKeyPair,
  signVerificationReport,
  verifySignedVerificationReport
} from '../docs/aml-signed-verification-report.js';
import { createSignedVerificationQuorum, verifySignedVerificationQuorum } from '../docs/aml-signed-verification-quorum.js';

function report(verifier, artifactHash = 'a'.repeat(64), valid = true) {
  return {
    schema: 'aml-verification-report/1',
    prototype: true,
    verifier,
    artifact_type: 'aml-witness-bundle/1',
    valid,
    reason: valid ? 'AML_WITNESS_BUNDLE_VALID' : 'AML_SESSION_SIGNATURE_INVALID',
    checked_at: '2030-01-01T00:05:00.000Z',
    artifact_hash: artifactHash,
    session_key_fingerprint: null,
    challenge_expires_at: '2030-01-01T00:10:00.000Z',
    checks: { bundle_integrity: true, session_signature: valid },
    notes: []
  };
}

test('signed verification report detects report mutation', async () => {
  const keys = await createVerifierKeyPair();
  const envelope = await signVerificationReport(report('verifier-a'), keys);
  assert.equal((await verifySignedVerificationReport(envelope)).valid, true);

  const tampered = structuredClone(envelope);
  tampered.report.valid = false;
  const check = await verifySignedVerificationReport(tampered);
  assert.equal(check.valid, false);
  assert.equal(check.reason, 'AML_SIGNED_REPORT_SIGNATURE_INVALID');
});

test('signed reports reject live claims that the signature did not cover', async () => {
  const keys = await createVerifierKeyPair();
  const envelope = await signVerificationReport(report('verifier-a'), keys);
  Object.defineProperty(envelope.report, 'unbound_claim', { value: 'approved by external auditor' });
  const check = await verifySignedVerificationReport(envelope);
  assert.equal(check.valid, false);
  assert.equal(check.reason, 'AML_CANONICAL_JSON_NON_JSON_OBJECT');
  await assert.rejects(
    () => createSignedVerificationQuorum([envelope], { threshold: 1 }),
    /AML_CANONICAL_JSON_NON_JSON_OBJECT/
  );
  await assert.rejects(
    () => signVerificationReport(envelope.report, keys),
    /AML_CANONICAL_JSON_NON_JSON_OBJECT/
  );
});

test('signed verification quorum requires distinct valid key fingerprints', async () => {
  const keyA = await createVerifierKeyPair();
  const keyB = await createVerifierKeyPair();
  const envelopeA = await signVerificationReport(report('verifier-a'), keyA);
  const envelopeB = await signVerificationReport(report('verifier-b'), keyB);
  const quorum = await createSignedVerificationQuorum([envelopeA, envelopeB], { threshold: 2 });
  assert.equal(quorum.summary.distinct_keys, 2);
  assert.equal(quorum.summary.valid_reports, 2);
  assert.equal(quorum.summary.threshold_met, true);
  assert.equal(quorum.summary.unanimous, true);
});

test('saved signed quorum recomputes signatures, summary, threshold, and claim boundary', async () => {
  const envelopeA = await signVerificationReport(report('verifier-a'), await createVerifierKeyPair());
  const envelopeB = await signVerificationReport(report('verifier-b'), await createVerifierKeyPair());
  const quorum = await createSignedVerificationQuorum([envelopeA, envelopeB], { threshold: 2 });
  const saved = JSON.parse(JSON.stringify(quorum));
  const verified = await verifySignedVerificationQuorum(saved);
  assert.equal(verified.valid, true);
  assert.equal(verified.threshold_met, true);

  const wrongSchema = await verifySignedVerificationQuorum({ schema: 'other-quorum/1' });
  assert.equal(wrongSchema.valid, false);
  assert.equal(wrongSchema.threshold_met, false);

  const inflated = structuredClone(saved);
  inflated.summary.distinct_keys = 3;
  assert.equal((await verifySignedVerificationQuorum(inflated)).reason, 'AML_SIGNED_QUORUM_MISMATCH');

  const rewritten = structuredClone(saved);
  rewritten.claim_boundary = 'Certified by an independent authority';
  assert.equal((await verifySignedVerificationQuorum(rewritten)).valid, false);

  const changedReport = structuredClone(saved);
  changedReport.signed_reports[0].report.reason = 'changed after signing';
  assert.equal((await verifySignedVerificationQuorum(changedReport)).valid, false);

  const hiddenClaim = structuredClone(saved);
  Object.defineProperty(hiddenClaim, 'approval', { value: 'unbound' });
  assert.equal((await verifySignedVerificationQuorum(hiddenClaim)).reason, 'AML_CANONICAL_JSON_NON_JSON_OBJECT');
});

test('reusing one verifier key cannot satisfy a two-key threshold', async () => {
  const key = await createVerifierKeyPair();
  const envelopeA = await signVerificationReport(report('verifier-a'), key);
  const envelopeB = await signVerificationReport(report('verifier-b'), key);
  const quorum = await createSignedVerificationQuorum([envelopeA, envelopeB], { threshold: 2 });
  assert.equal(quorum.summary.distinct_keys, 1);
  assert.equal(quorum.summary.valid_reports, 2);
  assert.equal(quorum.summary.threshold_met, false);
  const verified = await verifySignedVerificationQuorum(JSON.parse(JSON.stringify(quorum)));
  assert.equal(verified.valid, true);
  assert.equal(verified.threshold_met, false);
});

test('a correctly signed invalid report is dissent and cannot satisfy the distinct-key quorum', async () => {
  const keyA = await createVerifierKeyPair();
  const keyB = await createVerifierKeyPair();
  const envelopeA1 = await signVerificationReport(report('verifier-a-1'), keyA);
  const envelopeA2 = await signVerificationReport(report('verifier-a-2'), keyA);
  const dissent = await signVerificationReport(report('verifier-b', 'a'.repeat(64), false), keyB);

  const quorum = await createSignedVerificationQuorum([envelopeA1, envelopeA2, dissent], { threshold: 2 });
  assert.equal(quorum.summary.valid_signatures, 3);
  assert.equal(quorum.summary.valid_reports, 2);
  assert.equal(quorum.summary.invalid_reports, 1);
  assert.equal(quorum.summary.distinct_keys, 1);
  assert.equal(quorum.summary.threshold_met, false);
  assert.equal(quorum.summary.unanimous, false);
  assert.ok(quorum.summary.disagreement_reasons.includes('AML_SESSION_SIGNATURE_INVALID'));
});

test('signed verification quorum rejects mixed artifact hashes', async () => {
  const keyA = await createVerifierKeyPair();
  const keyB = await createVerifierKeyPair();
  const envelopeA = await signVerificationReport(report('verifier-a', 'a'.repeat(64)), keyA);
  const envelopeB = await signVerificationReport(report('verifier-b', 'b'.repeat(64)), keyB);
  await assert.rejects(
    () => createSignedVerificationQuorum([envelopeA, envelopeB], { threshold: 2 }),
    /AML_SIGNED_QUORUM_ARTIFACT_HASH_MISMATCH/
  );
});

test('signed quorum cannot count a report without a bound artifact as an endorsement', async () => {
  const good = await signVerificationReport(report('verifier-a'), await createVerifierKeyPair());
  const unboundReport = report('verifier-b');
  unboundReport.artifact_hash = null;
  const unbound = await signVerificationReport(unboundReport, await createVerifierKeyPair());
  assert.equal((await verifySignedVerificationReport(unbound)).valid, true);
  await assert.rejects(
    () => createSignedVerificationQuorum([good, unbound], { threshold: 2 }),
    /AML_SIGNED_QUORUM_ARTIFACT_HASH_REQUIRED/
  );
});

test('signed quorum rejects truthy non-boolean verdicts even with distinct valid signatures', async () => {
  const good = await signVerificationReport(report('verifier-a'), await createVerifierKeyPair());
  const malformedReport = report('verifier-b');
  malformedReport.valid = 'false';
  const malformed = await signVerificationReport(malformedReport, await createVerifierKeyPair());
  assert.equal((await verifySignedVerificationReport(malformed)).valid, true);
  await assert.rejects(
    () => createSignedVerificationQuorum([good, malformed], { threshold: 2 }),
    /AML_SIGNED_QUORUM_REPORT_VERDICT_INVALID/
  );
});
