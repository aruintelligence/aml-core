import test from 'node:test';
import assert from 'node:assert/strict';

import { canonicalJSONStringifyBrowser, sealBrowserReceipt,
  sha256Browser } from '../docs/aml-browser-integrity.js';
import { createBrowserEvidence } from '../docs/aml-browser-evidence.js';
import { createVerificationChallenge, verifyVerificationChallenge } from '../docs/aml-verification-challenge.js';
import {
  createSessionAttestation,
  verifySessionAttestation,
  resetAMLSessionKey
} from '../docs/aml-session-attestation.js';
import { createWitnessBundle, exportWitnessBundle, verifyWitnessBundle,
  witnessBundlePayload } from '../docs/aml-witness-bundle.js';
import { witnessVerificationReport } from '../docs/aml-verification-report.js';

function makeReceipt() {
  return {
    schema: 'aml-dom-receipt/1',
    prototype: true,
    revision: 1,
    reason: 'node-webcrypto-test',
    url: 'https://example.test/',
    generated_at: '2026-09-08T12:00:00.000Z',
    totals: { evaluated: 1, allowed: 0, suppressed: 1, errors: 0 },
    decisions: [{
      ok: true,
      index: 0,
      id: 'pressure',
      purpose: 'Create urgency',
      attention_cost: 5,
      restoration_value: 1,
      render_allowed: false
    }]
  };
}

async function createFixture() {
  resetAMLSessionKey();
  globalThis.__AML_ZONE_VIOLATIONS__ = [{
    schema: 'aml-zone-violation/1',
    prototype: true,
    zone_id: 'ai-zone',
    element_id: 'undeclared',
    tag: 'div',
    reason: 'undeclared-direct-child:test',
    observed_at: '2026-09-08T12:00:00.000Z'
  }];
  const receipt = await sealBrowserReceipt(makeReceipt());
  const evidence = await createBrowserEvidence(receipt, { url: 'https://example.test/' });
  const challenge = createVerificationChallenge({ ttl_ms: 60000 });
  const attestation = await createSessionAttestation({ evidence, challenge });
  const bundle = await createWitnessBundle({ evidence, challenge, attestation });
  return { receipt, evidence, challenge, attestation, bundle };
}

test('detached witness bundle verifies under Node WebCrypto', async () => {
  const fixture = await createFixture();
  const attestationCheck = await verifySessionAttestation(fixture);
  assert.equal(attestationCheck.valid, true);
  const bundleCheck = await verifyWitnessBundle(fixture.bundle);
  assert.equal(bundleCheck.valid, true);
  assert.equal(bundleCheck.reason, 'AML_WITNESS_BUNDLE_VALID');
});

test('detached witness bundle rejects evidence mutation', async () => {
  const { bundle } = await createFixture();
  const mutated = structuredClone(bundle);
  mutated.evidence.receipt.decisions[0].purpose = 'changed-after-signing';
  const check = await verifyWitnessBundle(mutated);
  assert.equal(check.valid, false);
  assert.notEqual(check.reason, 'AML_WITNESS_BUNDLE_VALID');
});

test('witness report records only verification steps actually passed', async () => {
  const { bundle, challenge } = await createFixture();
  const complete = await verifyWitnessBundle(bundle, { expectedChallenge: challenge });
  assert.equal(complete.valid, true);
  assert.deepEqual(witnessVerificationReport(bundle, complete).checks, {
    bundle_integrity: true,
    receipt_integrity: true,
    evidence_integrity: true,
    challenge_freshness: true,
    challenge_binding: true,
    session_signature: true,
    verifier_held_challenge: true
  });

  const selfContained = await verifyWitnessBundle(bundle);
  assert.equal(selfContained.valid, true);
  assert.equal(witnessVerificationReport(bundle, selfContained).checks.verifier_held_challenge, false);

  const damaged = structuredClone(bundle);
  damaged.evidence.receipt.decisions[0].purpose = 'tampered';
  const unsealed = await verifyWitnessBundle(damaged, { expectedChallenge: challenge });
  assert.equal(unsealed.reason, 'AML_WITNESS_BUNDLE_HASH_MISMATCH');
  assert.deepEqual(Object.values(witnessVerificationReport(damaged, unsealed).checks),
    Array(7).fill(false));

  damaged.integrity.value = await sha256Browser(witnessBundlePayload(damaged));
  const invalidReceipt = await verifyWitnessBundle(damaged, { expectedChallenge: challenge });
  assert.equal(invalidReceipt.reason, 'AML_SESSION_EVIDENCE_INVALID');
  assert.deepEqual(witnessVerificationReport(damaged, invalidReceipt).checks, {
    bundle_integrity: true,
    receipt_integrity: false,
    evidence_integrity: false,
    challenge_freshness: false,
    challenge_binding: false,
    session_signature: false,
    verifier_held_challenge: true
  });

  const badSignature = structuredClone(bundle);
  badSignature.attestation.signature = 'A'.repeat(86);
  badSignature.integrity.value = await sha256Browser(witnessBundlePayload(badSignature));
  const signatureResult = await verifyWitnessBundle(badSignature, { expectedChallenge: challenge });
  assert.equal(signatureResult.reason, 'AML_SESSION_SIGNATURE_INVALID');
  assert.deepEqual(witnessVerificationReport(badSignature, signatureResult).checks, {
    bundle_integrity: true,
    receipt_integrity: true,
    evidence_integrity: true,
    challenge_freshness: true,
    challenge_binding: true,
    session_signature: false,
    verifier_held_challenge: true
  });
});

test('session attestation rejects a verifier challenge mismatch', async () => {
  const { evidence, attestation } = await createFixture();
  const otherChallenge = createVerificationChallenge({ ttl_ms: 60000 });
  const check = await verifySessionAttestation({ evidence, challenge: otherChallenge, attestation });
  assert.equal(check.valid, false);
  assert.equal(check.reason, 'AML_SESSION_CHALLENGE_MISMATCH');
});

test('expired challenge fails detached verification', async () => {
  const { bundle } = await createFixture();
  const future = Date.parse(bundle.challenge.expires_at) + 1;
  const check = await verifyWitnessBundle(bundle, { now: future });
  assert.equal(check.valid, false);
  assert.equal(check.reason, 'AML_CHALLENGE_EXPIRED');
});

test('a resealed witness must have a coherent creation timeline', async () => {
  const { bundle, challenge, attestation } = await createFixture();
  const now = Math.max(Date.now(), Date.parse(bundle.created_at));
  const check = async (name, change, reason, replayNow = now) => {
    const altered = structuredClone(bundle);
    change(altered);
    altered.integrity.value = await sha256Browser(witnessBundlePayload(altered));
    const result = await verifyWitnessBundle(altered, {
      now: replayNow, expectedChallenge: altered.challenge
    });
    assert.equal(result.valid, false, name);
    assert.equal(result.reason, reason, name);
    assert.equal(result.checks.session_signature, true, name);
  };
  await check('invalid-calendar-date', copy => {
    copy.created_at = '2030-02-30T00:00:00.000Z';
  }, 'AML_WITNESS_BUNDLE_TIME_INVALID');
  await check('before-attestation', copy => {
    copy.created_at = new Date(Date.parse(attestation.issued_at) - 1).toISOString();
  }, 'AML_WITNESS_BUNDLE_TIME_ORDER_INVALID');
  await check('after-expiry', copy => {
    copy.created_at = new Date(Date.parse(challenge.expires_at) + 1).toISOString();
  }, 'AML_WITNESS_BUNDLE_TIME_ORDER_INVALID');
  await check('future-creation-inside-challenge', copy => {
    copy.created_at = new Date(now + 30000).toISOString();
  }, 'AML_WITNESS_BUNDLE_NOT_YET_CREATED');
  await check('attestation-before-challenge', copy => {
    copy.challenge.issued_at = new Date(Date.parse(attestation.issued_at) + 1).toISOString();
  }, 'AML_WITNESS_BUNDLE_TIME_ORDER_INVALID',
  Math.max(now, Date.parse(attestation.issued_at) + 1));
});

test('bundle creation refuses an attestation dated before challenge issue', async () => {
  const { evidence, challenge, attestation } = await createFixture();
  challenge.issued_at = new Date(Date.parse(attestation.issued_at) + 1).toISOString();
  // The session signature covers nonce and expiry, not the challenge issue.
  // Let the new issue time pass so only the bundle chronology rejects it.
  await new Promise(resolve => setTimeout(resolve, 10));
  await assert.rejects(createWitnessBundle({ evidence, challenge, attestation }),
    /AML_WITNESS_BUNDLE_TIME_ORDER_INVALID/);
});

test('signed witness cannot pass before its challenge issue time', async () => {
  const { bundle, challenge } = await createFixture();
  const beforeIssue = Date.parse(challenge.issued_at) - 1;
  assert.equal(verifyVerificationChallenge(challenge, { now: beforeIssue }).reason,
    'AML_CHALLENGE_NOT_YET_VALID');
  for (const options of [{ now: beforeIssue }, { now: beforeIssue, expectedChallenge: challenge }]) {
    const result = await verifyWitnessBundle(bundle, options);
    assert.equal(result.valid, false);
    assert.equal(result.reason, 'AML_CHALLENGE_NOT_YET_VALID');
  }
  assert.equal(verifyVerificationChallenge(challenge, { now: Date.parse(challenge.issued_at) }).valid, true);
});

test('invalid verifier clocks and malformed time fields fail closed', async () => {
  const { bundle, challenge } = await createFixture();
  for (const now of [NaN, Infinity, 'not-a-clock', null]) {
    assert.equal(verifyVerificationChallenge(challenge, { now }).reason, 'AML_CHALLENGE_TIME_INVALID');
    for (const options of [{ now }, { now, expectedChallenge: challenge }]) {
      const result = await verifyWitnessBundle(bundle, options);
      assert.equal(result.valid, false);
      assert.equal(result.reason, 'AML_CHALLENGE_TIME_INVALID');
    }
  }
  assert.equal(verifyVerificationChallenge({ ...challenge, issued_at: 2030 }).reason,
    'AML_CHALLENGE_TIME_INVALID');
});

test('challenge creation rejects invalid durations before producing an artifact', () => {
  for (const ttl_ms of [0, -1, 0.5, '60000', NaN, Infinity, Number.MAX_SAFE_INTEGER]) {
    assert.throws(() => createVerificationChallenge({ ttl_ms }), /AML_CHALLENGE_TTL_INVALID/);
  }
  const challenge = createVerificationChallenge({ ttl_ms: 1 });
  assert.equal(verifyVerificationChallenge(challenge, { now: Date.parse(challenge.issued_at) }).valid, true);
});

test('a hidden bundle field preserves the old canonical bytes but fails verification and export', async () => {
  const { bundle } = await createFixture();
  const canonical = canonicalJSONStringifyBrowser(bundle);
  Object.defineProperty(bundle, 'unbound_claim', { value: 'added after signing' });
  assert.equal(canonicalJSONStringifyBrowser(bundle), canonical);
  assert.equal((await verifyWitnessBundle(bundle)).reason, 'AML_CANONICAL_JSON_NON_JSON_OBJECT');
  assert.throws(() => exportWitnessBundle(bundle), /AML_CANONICAL_JSON_NON_JSON_OBJECT/);
});

test('a hidden challenge field fails direct challenge, signature, and bundle checks', async () => {
  const { bundle, evidence, challenge, attestation } = await createFixture();
  const canonical = canonicalJSONStringifyBrowser(bundle);
  Object.defineProperty(challenge, 'unbound_claim', { value: 'added after signing' });
  assert.equal(canonicalJSONStringifyBrowser(bundle), canonical);
  assert.equal(verifyVerificationChallenge(challenge).reason, 'AML_CANONICAL_JSON_NON_JSON_OBJECT');
  assert.equal((await verifySessionAttestation({ evidence, challenge, attestation })).valid, false);
  assert.equal((await verifyWitnessBundle(bundle)).reason, 'AML_CANONICAL_JSON_NON_JSON_OBJECT');
});

test('an unsigned hidden attestation field fails direct signature and bundle checks', async () => {
  const { bundle, evidence, challenge, attestation } = await createFixture();
  const canonical = canonicalJSONStringifyBrowser(bundle);
  Object.defineProperty(attestation.session_public_key_jwk, 'unbound_claim', { value: 'added' });
  assert.equal(canonicalJSONStringifyBrowser(bundle), canonical);
  assert.equal((await verifySessionAttestation({ evidence, challenge, attestation })).reason,
    'AML_CANONICAL_JSON_NON_JSON_OBJECT');
  assert.equal((await verifyWitnessBundle(bundle)).reason, 'AML_CANONICAL_JSON_NON_JSON_OBJECT');
  await assert.rejects(createWitnessBundle({ evidence, challenge, attestation }),
    /AML_CANONICAL_JSON_NON_JSON_OBJECT/);
});

test('a witness bundle checks its declared integrity method and exact fields', async () => {
  const { bundle } = await createFixture();
  const originalHash = await sha256Browser(witnessBundlePayload(bundle));
  for (const [mutate, reason] of [
    [(copy) => { copy.integrity.canonicalization = 'other-json'; }, 'AML_WITNESS_BUNDLE_CANONICALIZATION_UNSUPPORTED'],
    [(copy) => { copy.integrity.algorithm = 'SHA-1'; }, 'AML_WITNESS_BUNDLE_ALGORITHM_UNSUPPORTED'],
    [(copy) => { copy.integrity.extra = 'unsigned'; }, 'AML_WITNESS_BUNDLE_INTEGRITY_INVALID'],
    [(copy) => { copy.integrity.value = 'not-a-digest'; }, 'AML_WITNESS_BUNDLE_INTEGRITY_INVALID']
  ]) {
    const copy = structuredClone(bundle);
    mutate(copy);
    assert.equal(await sha256Browser(witnessBundlePayload(copy)), originalHash);
    assert.equal((await verifyWitnessBundle(copy)).reason, reason);
  }
});

test('an invalid challenge cannot be signed', async () => {
  const { evidence, challenge } = await createFixture();
  challenge[Symbol('unbound')] = 'claim';
  await assert.rejects(createSessionAttestation({ evidence, challenge }),
    /AML_CANONICAL_JSON_NON_JSON_OBJECT/);
});

test('verifier-held challenge detects a changed issued_at even after the bundle is rehashed', async () => {
  const { bundle, challenge } = await createFixture();
  const heldChallenge = structuredClone(challenge);
  assert.equal((await verifyWitnessBundle(bundle, { expectedChallenge: heldChallenge })).valid, true);
  challenge.issued_at = new Date(Date.parse(challenge.issued_at) - 1000).toISOString();
  bundle.integrity.value = await sha256Browser(witnessBundlePayload(bundle));
  // The ephemeral signature binds the nonce and expiration, not issued_at.
  assert.equal((await verifyWitnessBundle(bundle)).valid, true);
  const result = await verifyWitnessBundle(bundle, { expectedChallenge: heldChallenge });
  assert.equal(result.valid, false);
  assert.equal(result.reason, 'AML_WITNESS_BUNDLE_CHALLENGE_MISMATCH');
});
