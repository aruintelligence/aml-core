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
import { createSignedVerificationQuorum } from '../docs/aml-signed-verification-quorum.js';

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

test('reusing one verifier key cannot satisfy a two-key threshold', async () => {
  const key = await createVerifierKeyPair();
  const envelopeA = await signVerificationReport(report('verifier-a'), key);
  const envelopeB = await signVerificationReport(report('verifier-b'), key);
  const quorum = await createSignedVerificationQuorum([envelopeA, envelopeB], { threshold: 2 });
  assert.equal(quorum.summary.distinct_keys, 1);
  assert.equal(quorum.summary.valid_reports, 2);
  assert.equal(quorum.summary.threshold_met, false);
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
