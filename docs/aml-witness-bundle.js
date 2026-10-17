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

// Bundle and attestation creation times are claims inside the supplied JSON.
// Use the same narrow UTC millisecond spelling as the signed report profile
// so malformed dates and time-zone aliases cannot evade chronology checks.
function canonicalTime(value) {
  if (typeof value !== 'string' ||
      !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(value)) return null;
  const time = Date.parse(value);
  return Number.isFinite(time) && new Date(time).toISOString() === value ? time : null;
}

function bundleTimeFailure(bundle, now) {
  const attested = canonicalTime(bundle.attestation.issued_at);
  const created = canonicalTime(bundle.created_at);
  const evidenced = canonicalTime(bundle.evidence.generated_at);
  const hasReceiptTime = Object.hasOwn(bundle.evidence.receipt, 'generated_at');
  const receipted = hasReceiptTime ? canonicalTime(bundle.evidence.receipt.generated_at) : null;
  if (attested === null || created === null || evidenced === null ||
      (hasReceiptTime && receipted === null)) return 'AML_WITNESS_BUNDLE_TIME_INVALID';
  if ((hasReceiptTime && receipted > evidenced) || evidenced > attested) {
    return 'AML_WITNESS_BUNDLE_TIME_ORDER_INVALID';
  }
  if (attested < Date.parse(bundle.challenge.issued_at) || created < attested ||
      created > Date.parse(bundle.challenge.expires_at)) {
    return 'AML_WITNESS_BUNDLE_TIME_ORDER_INVALID';
  }
  return created > now ? 'AML_WITNESS_BUNDLE_NOT_YET_CREATED' : null;
}

export async function createWitnessBundle({ evidence, challenge, attestation }) {
  const attestationCheck = await verifySessionAttestation({ evidence, challenge, attestation });
  if (!attestationCheck.valid) throw new Error(attestationCheck.reason);
  const createdNow = Date.now();
  const bundle = {
    schema: 'aml-witness-bundle/1',
    prototype: true,
    created_at: new Date(createdNow).toISOString(),
    evidence,
    challenge,
    attestation
  };
  const timeFailure = bundleTimeFailure(bundle, createdNow);
  if (timeFailure) throw new Error(timeFailure);
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
    const timeFailure = bundleTimeFailure(bundle, now);
    if (timeFailure) return fail(timeFailure);
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
