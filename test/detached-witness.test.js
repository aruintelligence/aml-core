import test from 'node:test';
import assert from 'node:assert/strict';

import { sealBrowserReceipt } from '../docs/aml-browser-integrity.js';
import { createBrowserEvidence } from '../docs/aml-browser-evidence.js';
import { createVerificationChallenge } from '../docs/aml-verification-challenge.js';
import {
  createSessionAttestation,
  verifySessionAttestation,
  resetAMLSessionKey
} from '../docs/aml-session-attestation.js';
import { createWitnessBundle, verifyWitnessBundle } from '../docs/aml-witness-bundle.js';

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
