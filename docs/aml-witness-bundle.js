// ĀML witness bundle — SHIPPED reference prototype.
// Packages evidence + verifier challenge + ephemeral-session attestation into one portable JSON object.

import { canonicalJSONStringifyBrowser, sha256Browser } from './aml-browser-integrity.js';
import { verifySessionAttestation } from './aml-session-attestation.js';

export function witnessBundlePayload(bundle) {
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

export async function verifyWitnessBundle(bundle, { now = Date.now() } = {}) {
  try {
    if (!bundle?.integrity || bundle.integrity.schema !== 'aml-integrity/1') {
      return { valid: false, reason: 'AML_WITNESS_BUNDLE_UNSEALED' };
    }
    const expected = await sha256Browser(witnessBundlePayload(bundle));
    if (expected !== bundle.integrity.value) {
      return { valid: false, reason: 'AML_WITNESS_BUNDLE_HASH_MISMATCH', expected, observed: bundle.integrity.value };
    }
    const attestation = await verifySessionAttestation({
      evidence: bundle.evidence,
      challenge: bundle.challenge,
      attestation: bundle.attestation,
      now
    });
    if (!attestation.valid) return { valid: false, reason: attestation.reason, attestation };
    return {
      valid: true,
      reason: 'AML_WITNESS_BUNDLE_VALID',
      evidence_hash: bundle.evidence.integrity.value,
      session_key_fingerprint: bundle.attestation.session_key_fingerprint,
      challenge_expires_at: bundle.challenge.expires_at,
      attestation
    };
  } catch (error) {
    return { valid: false, reason: error?.message || 'AML_WITNESS_BUNDLE_VERIFY_ERROR' };
  }
}

export function exportWitnessBundle(bundle) {
  return canonicalJSONStringifyBrowser(bundle);
}
