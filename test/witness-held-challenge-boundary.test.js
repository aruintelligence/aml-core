// Release-blocker regression: js/user-controlled-bypass at docs/aml-witness-bundle.js
// (optional verifier-held challenge). Attacker model: the party presenting a
// bundle controls every byte of it, including the challenge it carries, and
// can generate challenges, evidence and ephemeral session keys locally. The
// relying party controls only its own retained challenge and reads
// `verified` (library) or HTTP 200 (service). Synthetic fixtures only.
import test from 'node:test';
import assert from 'node:assert/strict';
import { once } from 'node:events';
import { sealBrowserReceipt } from '../docs/aml-browser-integrity.js';
import { createBrowserEvidence } from '../docs/aml-browser-evidence.js';
import { createVerificationChallenge } from '../docs/aml-verification-challenge.js';
import { createSessionAttestation, resetAMLSessionKey } from '../docs/aml-session-attestation.js';
import { createWitnessBundle, verifyWitnessBundle } from '../docs/aml-witness-bundle.js';
import { createAmlHttpServer } from '../index.js';

async function attackerBundle() {
  // Everything below runs on the attacker's machine; nothing came from the relying party.
  resetAMLSessionKey();
  const receipt = await sealBrowserReceipt({ schema: 'aml-dom-receipt/1', prototype: true, revision: 1,
    reason: 'synthetic-attacker-fixture', url: 'https://attacker.example.test/',
    generated_at: new Date(Date.now() - 1000).toISOString(),
    totals: { evaluated: 0, allowed: 0, suppressed: 0, errors: 0 }, decisions: [] });
  const evidence = await createBrowserEvidence(receipt, { url: 'https://attacker.example.test/' });
  const challenge = createVerificationChallenge({ ttl_ms: 60000 });
  const attestation = await createSessionAttestation({ evidence, challenge });
  return createWitnessBundle({ evidence, challenge, attestation });
}

test('a self-made bundle is self-consistent but never verified without the relying party challenge', async () => {
  const bundle = await attackerBundle();
  const heldByRelyingParty = createVerificationChallenge({ ttl_ms: 60000 });
  const unheld = await verifyWitnessBundle(bundle);
  assert.equal(unheld.valid, true, 'historical self-consistency meaning is unchanged');
  assert.equal(unheld.verified, false, 'no retained challenge: the acceptance decision fails closed');
  assert.equal(unheld.checks.verifier_held_challenge, false);
  const substituted = await verifyWitnessBundle(bundle, { expectedChallenge: heldByRelyingParty });
  assert.equal(substituted.valid, false);
  assert.equal(substituted.verified, false);
  assert.equal(substituted.reason, 'AML_WITNESS_BUNDLE_CHALLENGE_MISMATCH');
  const matched = await verifyWitnessBundle(bundle, { expectedChallenge: bundle.challenge });
  assert.equal(matched.verified, true, 'positive control: a retained matching challenge verifies');
  for (const options of [{ expectedChallenge: undefined }, { expectedChallenge: null }, { now: Date.now() }]) {
    assert.notEqual((await verifyWitnessBundle(bundle, options)).verified, true, JSON.stringify(options));
  }
});

async function withServer(fn) {
  const server = createAmlHttpServer();
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  try { await fn(`http://127.0.0.1:${server.address().port}`); }
  finally { server.closeAllConnections?.(); server.close(); }
}

test('HTTP witness verification returns 200 only for the caller retained challenge', async () => {
  const bundle = await attackerBundle();
  const held = createVerificationChallenge({ ttl_ms: 60000 });
  await withServer(async base => {
    const post = body => fetch(`${base}/v1/verify-witness-bundle`, { method: 'POST',
      headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });
    const missing = await post({ bundle });
    assert.equal(missing.status, 400);
    assert.equal((await missing.json()).error, 'expected_challenge_required');
    for (const expected_challenge of [null, 'x', [], 7]) {
      assert.equal((await post({ bundle, expected_challenge })).status, 400);
    }
    const stale = await post({ bundle, now: Date.now() + 10 * 60000 });
    assert.equal(stale.status, 400, 'a caller clock alone can no longer produce a verdict');
    const substituted = await post({ bundle, expected_challenge: held });
    assert.equal(substituted.status, 422);
    const body = await substituted.json();
    assert.equal(body.verified, false);
    assert.equal(body.reason, 'AML_WITNESS_BUNDLE_CHALLENGE_MISMATCH');
    const matched = await post({ bundle, expected_challenge: bundle.challenge });
    assert.equal(matched.status, 200);
    const accepted = await matched.json();
    assert.equal(accepted.verified, true);
    assert.match(accepted.held_challenge_sha256, /^[a-f0-9]{64}$/);
  });
});

// Review of the related js/user-controlled-bypass alerts at
// docs/aml-session-attestation.js:129/132/143 and docs/aml-witness-bundle.js:117/120/123.
// Hypothesis: an attacker-chosen field value lets verification skip a check.
// Each guarded field is altered and the unkeyed bundle digest recomputed, as an
// attacker can. Every variant must fail; none may reach `valid` or `verified`.
test('attacker-controlled guard fields cannot skip a cryptographic check', async () => {
  const { sha256Browser } = await import('../docs/aml-browser-integrity.js');
  const { witnessBundlePayload } = await import('../docs/aml-witness-bundle.js');
  const bundle = await attackerBundle();
  const reseal = async copy => { copy.integrity.value = await sha256Browser(witnessBundlePayload(copy)); return copy; };
  const variants = {
    'integrity.schema': b => { b.integrity.schema = 'aml-integrity/0'; },
    'integrity.algorithm': b => { b.integrity.algorithm = 'SHA-1'; },
    'integrity.canonicalization': b => { b.integrity.canonicalization = 'none'; },
    'attestation.schema': b => { b.attestation.schema = 'aml-session-attestation/0'; },
    'attestation.algorithm': b => { b.attestation.algorithm = 'none'; },
    'attestation.evidence_hash': b => { b.attestation.evidence_hash = 'f'.repeat(64); },
    'attestation.challenge_nonce': b => { b.attestation.challenge_nonce = 'f'.repeat(64); },
    'attestation.challenge_expires_at': b => { b.attestation.challenge_expires_at = '2099-01-01T00:00:00.000Z'; },
    'attestation.session_public_key_jwk.crv': b => { b.attestation.session_public_key_jwk.crv = 'P-384'; },
    'attestation.session_key_fingerprint': b => { b.attestation.session_key_fingerprint = 'f'.repeat(64); },
    'challenge.expires_at': b => { b.challenge.expires_at = '2099-01-01T00:00:00.000Z'; },
    'evidence.receipt': b => { b.evidence.receipt.reason = 'tampered'; }
  };
  for (const [name, mutate] of Object.entries(variants)) {
    const copy = structuredClone(bundle);
    mutate(copy);
    const sealed = name.startsWith('integrity.') ? copy : await reseal(copy);
    for (const options of [{}, { expectedChallenge: sealed.challenge }]) {
      const result = await verifyWitnessBundle(sealed, options);
      assert.equal(result.valid, false, name);
      assert.equal(result.verified, false, name);
    }
  }
});
