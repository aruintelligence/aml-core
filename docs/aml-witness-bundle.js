// ĀML witness bundle — SHIPPED reference prototype.
// Packages evidence + verifier challenge + ephemeral-session attestation into one portable JSON object.

import { assertBrowserJSON, canonicalJSONStringifyBrowser, sha256Browser } from './aml-browser-integrity.js';
import { verifySessionAttestation } from './aml-session-attestation.js';
import { verifyVerificationChallenge } from './aml-verification-challenge.js';

export function witnessBundlePayload(bundle) {
  assertBrowserJSON(bundle);
  if (!bundle || bundle.schema !== 'aml-witness-bundle/1') throw new Error('AML_WITNESS_BUNDLE_INVALID');
  const { integrity, ...payload } = bundle;
  return payload;
}

export async function createWitnessBundle({ evidence, challenge, attestation }) {
  const attestationCheck = await verifySessionAttestation({ evidence, challenge, attestation });
  if (!attestationCheck.valid) throw new Error(attestationCheck.reason);
  const bundle = {
    schema: 'aml-witness-bundle/1',
    prototype: true,
    created_at: new Date().toISOString(),
    evidence,
    challenge,
    attestation
  };
  bundle.integrity = {
    schema: 'aml-integrity/1',
    algorithm: 'SHA-256',
    canonicalization: 'sorted-json-v1',
    value: await sha256Browser(witnessBundlePayload({ ...bundle, integrity: null }))
  };
  return bundle;
}

export async function verifyWitnessBundle(bundle, { now = Date.now(), expectedChallenge } = {}) {
  const checks = {
    bundle_integrity: false,
    receipt_integrity: false,
    evidence_integrity: false,
    challenge_freshness: false,
    challenge_binding: false,
    session_signature: false,
    verifier_held_challenge: false
  };
  const fail = (reason, extra = {}) => ({ valid: false, reason, checks: { ...checks }, ...extra });
  try {
    assertBrowserJSON(bundle);
    if (!bundle?.integrity || bundle.integrity.schema !== 'aml-integrity/1') {
      return fail('AML_WITNESS_BUNDLE_UNSEALED');
    }
    if (bundle.integrity.algorithm !== 'SHA-256') {
      return fail('AML_WITNESS_BUNDLE_ALGORITHM_UNSUPPORTED');
    }
    if (bundle.integrity.canonicalization !== 'sorted-json-v1') {
      return fail('AML_WITNESS_BUNDLE_CANONICALIZATION_UNSUPPORTED');
    }
    if (Object.keys(bundle.integrity).sort().join('|') !== 'algorithm|canonicalization|schema|value' ||
        !/^[a-f0-9]{64}$/.test(bundle.integrity.value)) {
      return fail('AML_WITNESS_BUNDLE_INTEGRITY_INVALID');
    }
    const expected = await sha256Browser(witnessBundlePayload(bundle));
    if (expected !== bundle.integrity.value) {
      return fail('AML_WITNESS_BUNDLE_HASH_MISMATCH', { expected, observed: bundle.integrity.value });
    }
    checks.bundle_integrity = true;
    if (expectedChallenge !== undefined) {
      const heldChallenge = verifyVerificationChallenge(expectedChallenge, { now });
      if (!heldChallenge.valid) return fail(heldChallenge.reason);
      if (canonicalJSONStringifyBrowser(bundle.challenge) !== canonicalJSONStringifyBrowser(expectedChallenge)) {
        return fail('AML_WITNESS_BUNDLE_CHALLENGE_MISMATCH');
      }
      checks.verifier_held_challenge = true;
    }
    const attestation = await verifySessionAttestation({
      evidence: bundle.evidence,
      challenge: bundle.challenge,
      attestation: bundle.attestation,
      now
    });
    for (const key of Object.keys(attestation.checks || {})) {
      if (Object.hasOwn(checks, key)) checks[key] = attestation.checks[key] === true;
    }
    if (!attestation.valid) return fail(attestation.reason, { attestation });
    return {
      valid: true,
      reason: 'AML_WITNESS_BUNDLE_VALID',
      checks: { ...checks },
      evidence_hash: bundle.evidence.integrity.value,
      session_key_fingerprint: bundle.attestation.session_key_fingerprint,
      challenge_expires_at: bundle.challenge.expires_at,
      attestation
    };
  } catch (error) {
    return fail(error?.message || 'AML_WITNESS_BUNDLE_VERIFY_ERROR');
  }
}

export function exportWitnessBundle(bundle) {
  assertBrowserJSON(bundle);
  return canonicalJSONStringifyBrowser(bundle);
}
