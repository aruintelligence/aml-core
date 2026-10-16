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
