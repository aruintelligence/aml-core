import test from 'node:test';
import assert from 'node:assert/strict';

import { canonicalJSONStringifyBrowser, sealBrowserReceipt,
  sha256Browser } from '../docs/aml-browser-integrity.js';
import { browserEvidencePayload, createBrowserEvidence } from '../docs/aml-browser-evidence.js';
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

test('direct session and bundle verification bind all inputs before Web Crypto yields', async () => {
  const source = await createFixture();
  const evidence = structuredClone(source.evidence);
  const challenge = structuredClone(source.challenge);
  const attestation = structuredClone(source.attestation);
  const sessionCheck = verifySessionAttestation({ evidence, challenge, attestation });
  evidence.receipt.decisions[0].purpose = 'changed after call';
  challenge.nonce = 'A'.repeat(43);
  attestation.signature = 'A'.repeat(86);
  const session = await sessionCheck;
  assert.equal(session.valid, true);
  assert.equal(session.evidence_hash, source.evidence.integrity.value);
  assert.equal((await verifySessionAttestation({ evidence, challenge, attestation })).valid, false);

  const bundle = structuredClone(source.bundle);
  const heldChallenge = structuredClone(source.challenge);
  const pending = verifyWitnessBundle(bundle, { expectedChallenge: heldChallenge });
  bundle.evidence.receipt.decisions[0].purpose = 'changed after call';
  bundle.attestation.signature = 'A'.repeat(86);
  heldChallenge.issued_at = '2030-01-01T00:00:00.000Z';
  const replay = await pending;
  assert.equal(replay.valid, true);
  assert.equal(replay.checks.verifier_held_challenge, true);
  assert.equal((await verifyWitnessBundle(bundle, { expectedChallenge: heldChallenge })).valid, false);
});

test('witness reports describe the verified snapshot after the caller edits its bundle', async () => {
  const { bundle, challenge } = await createFixture();
  const original = {
    artifact_hash: bundle.integrity.value,
    session_key_fingerprint: bundle.attestation.session_key_fingerprint,
    challenge_expires_at: bundle.challenge.expires_at
  };
  const pending = verifyWitnessBundle(bundle, { expectedChallenge: challenge });
  bundle.integrity.value = '0'.repeat(64);
  bundle.attestation.session_key_fingerprint = '1'.repeat(64);
  bundle.challenge.expires_at = '2030-01-01T00:00:00.000Z';
  const result = await pending;
  assert.equal(result.valid, true);
  assert.deepEqual(result.inspected, original);
  const report = witnessVerificationReport(bundle, result);
  for (const [field, value] of Object.entries(original)) {
    assert.equal(report[field], value, field);
  }
  assert.equal(report.valid, true);
  assert.equal((await verifyWitnessBundle(bundle, { expectedChallenge: challenge })).valid, false);
});

test('failed witness reports retain observed fields and omit malformed live inputs', async () => {
  const { bundle } = await createFixture();
  const originalHash = bundle.integrity.value;
  const failed = structuredClone(bundle);
  failed.attestation.signature = 'A'.repeat(86);
  const result = await verifyWitnessBundle(failed);
  assert.equal(result.reason, 'AML_WITNESS_BUNDLE_HASH_MISMATCH');
  failed.integrity.value = '0'.repeat(64);
  assert.equal(witnessVerificationReport(failed, result).artifact_hash, originalHash);

  const malformed = structuredClone(bundle);
  Object.defineProperty(malformed, 'hidden', { value: true });
  const rejected = await verifyWitnessBundle(malformed);
  assert.equal(rejected.reason, 'AML_CANONICAL_JSON_NON_JSON_OBJECT');
  assert.deepEqual(rejected.inspected, {
    artifact_hash: null, session_key_fingerprint: null, challenge_expires_at: null
  });
  assert.equal(witnessVerificationReport(malformed, rejected).artifact_hash, null);
});

test('witness creators package the inputs checked at call time', async () => {
  const source = await createFixture();
  const evidence = structuredClone(source.evidence);
  const challenge = structuredClone(source.challenge);
  const pendingAttestation = createSessionAttestation({ evidence, challenge });
  evidence.receipt.decisions[0].purpose = 'changed after call';
  challenge.nonce = 'A'.repeat(43);
  const attestation = await pendingAttestation;
  assert.equal(attestation.challenge_nonce, source.challenge.nonce);
  assert.equal((await verifySessionAttestation({ evidence: source.evidence,
    challenge: source.challenge, attestation })).valid, true);

  const bundleEvidence = structuredClone(source.evidence);
  const bundleChallenge = structuredClone(source.challenge);
  const bundleAttestation = structuredClone(attestation);
  const pendingBundle = createWitnessBundle({ evidence: bundleEvidence,
    challenge: bundleChallenge, attestation: bundleAttestation });
  bundleEvidence.receipt.decisions[0].purpose = 'changed after call';
  bundleChallenge.nonce = 'A'.repeat(43);
  bundleAttestation.signature = 'A'.repeat(86);
  const bundle = await pendingBundle;
  assert.equal(bundle.challenge.nonce, source.challenge.nonce);
  assert.equal((await verifyWitnessBundle(bundle, { expectedChallenge: source.challenge })).valid, true);
});

test('hidden call-time inputs cannot become valid by deletion during replay', async () => {
  const source = await createFixture();
  const held = structuredClone(source.challenge);
  Object.defineProperty(held, 'unbound', { value: true, configurable: true });
  const pending = verifyWitnessBundle(source.bundle, { expectedChallenge: held });
  delete held.unbound;
  assert.equal((await pending).reason, 'AML_CANONICAL_JSON_NON_JSON_OBJECT');
  assert.equal((await verifyWitnessBundle(source.bundle, { expectedChallenge: held })).valid, true);

  const attestation = structuredClone(source.attestation);
  Object.defineProperty(attestation.session_public_key_jwk, 'unbound',
    { value: true, configurable: true });
  const pendingSession = verifySessionAttestation({ evidence: source.evidence,
    challenge: source.challenge, attestation });
  delete attestation.session_public_key_jwk.unbound;
  assert.equal((await pendingSession).reason, 'AML_CANONICAL_JSON_NON_JSON_OBJECT');
});

test('sequential and concurrent attestations use isolated keys and remain replayable', async () => {
  const { evidence, challenge, attestation: first } = await createFixture();
  const second = await createSessionAttestation({ evidence, challenge });
  const challenges = [createVerificationChallenge(), createVerificationChallenge()];
  const concurrent = await Promise.all(challenges.map(next =>
    createSessionAttestation({ evidence, challenge: next })));
  const attestations = [first, second, ...concurrent];
  assert.equal(new Set(attestations.map(item => item.session_key_fingerprint)).size, 4);
  resetAMLSessionKey();
  assert.equal(globalThis.__AML_SESSION_ATTESTATION__, null);
  for (const [index, attestation] of attestations.entries()) {
    const retained = index < 2 ? challenge : challenges[index - 2];
    assert.equal((await verifySessionAttestation({ evidence, challenge: retained,
      attestation })).valid, true, `attestation ${index}`);
    const bundle = await createWitnessBundle({ evidence, challenge: retained, attestation });
    assert.equal((await verifyWitnessBundle(bundle, { expectedChallenge: retained })).valid,
      true, `bundle ${index}`);
  }
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

test('witness replay rejects alternate spellings of signed P-256 bytes', async () => {
  const { bundle, evidence, challenge, attestation } = await createFixture();
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
  const alternate = value => value.slice(0, -1) +
    alphabet[alphabet.indexOf(value.at(-1)) ^ 1];
  const signatureAlias = alternate(attestation.signature);
  assert.deepEqual(Buffer.from(signatureAlias, 'base64url'),
    Buffer.from(attestation.signature, 'base64url'));
  for (const [name, signature] of [
    ['unused-bits', signatureAlias],
    ['padding', `${attestation.signature}==`],
    ['whitespace', `${attestation.signature.slice(0, 10)} ${attestation.signature.slice(10)}`],
    ['truncated', attestation.signature.slice(0, -1)],
    ['null', null]
  ]) {
    const altered = structuredClone(bundle);
    altered.attestation.signature = signature;
    altered.integrity.value = await sha256Browser(witnessBundlePayload(altered));
    const direct = await verifySessionAttestation({ evidence, challenge,
      attestation: altered.attestation });
    const replay = await verifyWitnessBundle(altered, { expectedChallenge: challenge });
    assert.equal(direct.reason, 'AML_SESSION_SIGNATURE_ENCODING_INVALID', name);
    assert.equal(replay.reason, direct.reason, name);
    assert.equal(replay.checks.session_signature, false, name);
  }
  const keyAlias = structuredClone(bundle);
  const jwk = keyAlias.attestation.session_public_key_jwk;
  const alternateX = alternate(jwk.x);
  assert.deepEqual(Buffer.from(alternateX, 'base64url'), Buffer.from(jwk.x, 'base64url'));
  jwk.x = alternateX;
  keyAlias.attestation.session_key_fingerprint = await sha256Browser(jwk);
  keyAlias.integrity.value = await sha256Browser(witnessBundlePayload(keyAlias));
  assert.equal((await verifyWitnessBundle(keyAlias, { expectedChallenge: challenge })).reason,
    'AML_SESSION_KEY_ENCODING_INVALID');
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

test('receipt and evidence time claims cannot postdate their signed attestation', async () => {
  for (const [name, mutateReceipt, mutateEvidence, reason] of [
    ['receipt-after-evidence', receipt => {
      receipt.generated_at = new Date(Date.now() + 30000).toISOString();
    }, () => {}, 'AML_WITNESS_BUNDLE_TIME_ORDER_INVALID'],
    ['evidence-after-attestation', () => {}, evidence => {
      evidence.generated_at = new Date(Date.now() + 30000).toISOString();
    }, 'AML_WITNESS_BUNDLE_TIME_ORDER_INVALID'],
    ['invalid-receipt-date', receipt => {
      receipt.generated_at = '2030-02-30T00:00:00.000Z';
    }, () => {}, 'AML_WITNESS_BUNDLE_TIME_INVALID'],
    ['missing-evidence-time', () => {}, evidence => {
      delete evidence.generated_at;
    }, 'AML_WITNESS_BUNDLE_TIME_INVALID']
  ]) {
    const source = await createFixture();
    const receipt = structuredClone(source.receipt);
    mutateReceipt(receipt);
    await sealBrowserReceipt(receipt);
    const evidence = await createBrowserEvidence(receipt, { url: 'https://example.test/' });
    mutateEvidence(evidence);
    evidence.integrity.value = await sha256Browser(browserEvidencePayload(evidence));
    const challenge = createVerificationChallenge({ ttl_ms: 120000 });
    const attestation = await createSessionAttestation({ evidence, challenge });
    await assert.rejects(createWitnessBundle({ evidence, challenge, attestation }),
      new RegExp(reason), name);
    const bundle = {
      schema: 'aml-witness-bundle/1', prototype: true, created_at: new Date().toISOString(),
      evidence, challenge, attestation
    };
    bundle.integrity = { schema: 'aml-integrity/1', algorithm: 'SHA-256',
      canonicalization: 'sorted-json-v1', value: await sha256Browser(witnessBundlePayload(bundle)) };
    const result = await verifyWitnessBundle(bundle, { expectedChallenge: challenge });
    assert.equal(result.reason, reason, name);
    assert.equal(result.checks.session_signature, true, name);
  }
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

test('challenge times use exact UTC milliseconds across verifiers', async () => {
  const { bundle, challenge } = await createFixture();
  const offsetAlias = new Date(Date.parse(challenge.issued_at) + 3600000)
    .toISOString().replace('Z', '+01:00');
  for (const [name, field, value] of [
    ['invalid-calendar', 'issued_at', '2029-11-31T00:00:00.000Z'],
    ['rollover-hour', 'issued_at', '2030-01-01T24:00:00.000Z'],
    ['year-zero', 'issued_at', '0000-01-01T00:00:00.000Z'],
    ['offset-alias', 'issued_at', offsetAlias],
    ['submillisecond', 'issued_at', challenge.issued_at.replace('Z', '1Z')],
    ['missing-milliseconds', 'expires_at', challenge.expires_at.replace(/\.[0-9]{3}Z$/, 'Z')]
  ]) {
    const altered = { ...challenge, [field]: value };
    assert.equal(verifyVerificationChallenge(altered).reason, 'AML_CHALLENGE_TIME_INVALID', name);
    const resealed = structuredClone(bundle);
    resealed.challenge = altered;
    resealed.integrity.value = await sha256Browser(witnessBundlePayload(resealed));
    const result = await verifyWitnessBundle(resealed, { expectedChallenge: altered });
    assert.equal(result.reason, 'AML_CHALLENGE_TIME_INVALID', name);
  }
  assert.equal(verifyVerificationChallenge(challenge).valid, true);
});

test('challenge replay accepts only the generated field shape and canonical 32-byte nonce', async () => {
  const { bundle, challenge, evidence } = await createFixture();
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
  const alias = challenge.nonce.slice(0, -1) +
    alphabet[alphabet.indexOf(challenge.nonce.at(-1)) ^ 1];
  assert.deepEqual(Buffer.from(alias, 'base64url'), Buffer.from(challenge.nonce, 'base64url'));
  const cases = [
    ['missing-prototype', { prototype: undefined }, 'AML_CHALLENGE_INVALID'],
    ['false-prototype', { prototype: false }, 'AML_CHALLENGE_INVALID'],
    ['extra-claim', { issuer_verified: true }, 'AML_CHALLENGE_INVALID'],
    ['short-nonce', { nonce: challenge.nonce.slice(0, -1) }, 'AML_CHALLENGE_NONCE_INVALID'],
    ['padded-nonce', { nonce: `${challenge.nonce}=` }, 'AML_CHALLENGE_NONCE_INVALID'],
    ['nonce-byte-alias', { nonce: alias }, 'AML_CHALLENGE_NONCE_INVALID'],
    ['non-base64-nonce', { nonce: 'x'.repeat(42) + '!' }, 'AML_CHALLENGE_NONCE_INVALID']
  ];
  for (const [name, changes, reason] of cases) {
    const altered = { ...challenge, ...changes };
    if (Object.hasOwn(changes, 'prototype') && changes.prototype === undefined) {
      delete altered.prototype;
    }
    assert.equal(verifyVerificationChallenge(altered).reason, reason, name);
    await assert.rejects(createSessionAttestation({ evidence, challenge: altered }),
      new RegExp(reason), name);
    const resealed = structuredClone(bundle);
    resealed.challenge = altered;
    resealed.integrity.value = await sha256Browser(witnessBundlePayload(resealed));
    const result = await verifyWitnessBundle(resealed, { expectedChallenge: altered });
    assert.equal(result.reason, reason, name);
    assert.equal(result.checks.verifier_held_challenge, false, name);
  }
  assert.equal(verifyVerificationChallenge(challenge).valid, true);
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
  assert.equal((await verifyWitnessBundle(bundle)).valid, true);
  Object.defineProperty(bundle.challenge, 'unbound_claim', { value: 'added after signing' });
  assert.equal((await verifyWitnessBundle(bundle)).reason, 'AML_CANONICAL_JSON_NON_JSON_OBJECT');
});

test('an unsigned hidden attestation field fails direct signature and bundle checks', async () => {
  const { bundle, evidence, challenge, attestation } = await createFixture();
  const canonical = canonicalJSONStringifyBrowser(bundle);
  Object.defineProperty(attestation.session_public_key_jwk, 'unbound_claim', { value: 'added' });
  assert.equal(canonicalJSONStringifyBrowser(bundle), canonical);
  assert.equal((await verifySessionAttestation({ evidence, challenge, attestation })).reason,
    'AML_CANONICAL_JSON_NON_JSON_OBJECT');
  assert.equal((await verifyWitnessBundle(bundle)).valid, true);
  Object.defineProperty(bundle.attestation.session_public_key_jwk, 'unbound_claim', { value: 'added' });
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
  bundle.challenge.issued_at = new Date(Date.parse(challenge.issued_at) - 1000).toISOString();
  bundle.integrity.value = await sha256Browser(witnessBundlePayload(bundle));
  // The ephemeral signature binds the nonce and expiration, not issued_at.
  assert.equal((await verifyWitnessBundle(bundle)).valid, true);
  const result = await verifyWitnessBundle(bundle, { expectedChallenge: heldChallenge });
  assert.equal(result.valid, false);
  assert.equal(result.reason, 'AML_WITNESS_BUNDLE_CHALLENGE_MISMATCH');
});
