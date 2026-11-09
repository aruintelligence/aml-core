// ĀML witness bundle — SHIPPED reference prototype.
// Packages evidence + verifier challenge + ephemeral-session attestation into one portable JSON object.

import { assertBrowserJSON, canonicalJSONStringifyBrowser, sha256Browser,
  snapshotBrowserJSON } from './aml-browser-integrity.js';
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
  ({ evidence, challenge, attestation } = snapshotBrowserJSON({ evidence, challenge, attestation }));
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

// Authorization semantics (fail closed). `valid` means only that the bundle is
// internally consistent and `verified` that it also answered the caller's
// retained challenge. Neither field is permission to act. `authorized` is the
// only decision field: it is true only when every required condition below is
// the boolean `true`. Missing, unknown, or non-boolean conditions deny.
// Trust rule for time: the verifier trusts only its own clock. A caller may
// pass `now` (an outer verifier that already read the same clock, or a fixed
// test clock), and `valid`/`verified` are computed with it for compatibility,
// but `authorized` requires that value to be a finite number within
// WITNESS_AUTHORIZATION_CLOCK_SKEW_MS of this verifier's own reading. A stale
// or future caller clock therefore never authorizes.
export const WITNESS_AUTHORIZATION_CLOCK_SKEW_MS = 1000;
export const WITNESS_AUTHORIZATION_REQUIRED = Object.freeze([
  'bundle_valid', 'verifier_held_challenge', 'trusted_clock'
]);
const witnessAuthorizationDenials = Object.freeze({
  bundle_valid: 'AML_AUTHZ_BUNDLE_NOT_VALID',
  verifier_held_challenge: 'AML_AUTHZ_HELD_CHALLENGE_NOT_MATCHED',
  trusted_clock: 'AML_AUTHZ_CALLER_CLOCK_UNTRUSTED'
});

export function witnessAuthorizationDecision(conditions) {
  const deny = reasons => ({ schema: 'aml-authorization-decision/1', authorized: false,
    decision: 'deny', reasons, required: [...WITNESS_AUTHORIZATION_REQUIRED] });
  try {
    if (!conditions || typeof conditions !== 'object' || Array.isArray(conditions)) {
      return deny(['AML_AUTHZ_CONDITIONS_MISSING']);
    }
    const reasons = [];
    for (const name of WITNESS_AUTHORIZATION_REQUIRED) {
      if (!Object.hasOwn(conditions, name) || conditions[name] !== true) {
        reasons.push(witnessAuthorizationDenials[name]);
      }
    }
    if (Object.keys(conditions).some(name => !WITNESS_AUTHORIZATION_REQUIRED.includes(name))) {
      reasons.push('AML_AUTHZ_UNKNOWN_CONDITION');
    }
    if (reasons.length) return deny(reasons);
    return { schema: 'aml-authorization-decision/1', authorized: true, decision: 'allow',
      reasons: ['AML_AUTHZ_ALLOW'], required: [...WITNESS_AUTHORIZATION_REQUIRED] };
  } catch {
    return deny(['AML_AUTHZ_EVALUATION_ERROR']);
  }
}

export async function verifyWitnessBundle(bundle, options = {}) {
  const callerSuppliedClock = Object.hasOwn(options, 'now');
  // Avoid reading Date.now twice when an outer verifier already captured one
  // replay instant and supplied it through `now`.
  const localNow = callerSuppliedClock ? new Date().getTime() : Date.now();
  const now = callerSuppliedClock ? options.now : localNow;
  let expectedChallenge = Object.hasOwn(options, 'expectedChallenge')
    ? options.expectedChallenge : undefined;
  // Keep the local observation separate from a caller's optional test clock.
  // Neither value proves a trusted timestamp.
  const timing = {
    evaluated_at: Number.isFinite(localNow) && Math.abs(localNow) <= 8.64e15
      ? new Date(localNow).toISOString() : null,
    freshness_clock_source: callerSuppliedClock ? 'caller_supplied' : 'local_system'
  };
  const trustedClock = Number.isFinite(localNow) && (!callerSuppliedClock ||
    (typeof now === 'number' && Number.isFinite(now) &&
      Math.abs(now - localNow) <= WITNESS_AUTHORIZATION_CLOCK_SKEW_MS));
  const decide = (bundleValid, heldChallenge) => {
    const authorization = witnessAuthorizationDecision({
      bundle_valid: bundleValid, verifier_held_challenge: heldChallenge, trusted_clock: trustedClock
    });
    return { authorized: authorization.authorized, authorization };
  };
  const checks = {
    bundle_integrity: false,
    receipt_integrity: false,
    evidence_integrity: false,
    challenge_freshness: false,
    challenge_binding: false,
    session_signature: false,
    verifier_held_challenge: false
  };
  // Report construction may happen after the caller edits the original bundle.
  // Carry the claims read from this call's snapshot with every result, including
  // failed checks. Null means a field was missing or could not be safely read.
  let inspected = {
    artifact_hash: null,
    session_key_fingerprint: null,
    challenge_expires_at: null
  };
  // `valid` keeps its historical meaning: the bundle is internally consistent.
  // Anyone can assemble a self-consistent bundle around a challenge they made
  // themselves. `verified` adds that the caller's own retained challenge
  // matched. `authorized` (above) is the only field that grants permission.
  const fail = (reason, extra = {}) => ({
    ...extra, valid: false, verified: false, ...decide(false, false), reason,
    checks: { ...checks }, inspected: { ...inspected }, ...timing
  });
  try {
    let heldInputError;
    if (expectedChallenge !== undefined) {
      try { expectedChallenge = snapshotBrowserJSON(expectedChallenge); }
      catch (error) { heldInputError = error; }
    }
    bundle = snapshotBrowserJSON(bundle);
    const stringOrNull = value => typeof value === 'string' ? value : null;
    inspected = {
      artifact_hash: stringOrNull(bundle?.integrity?.value),
      session_key_fingerprint: stringOrNull(bundle?.attestation?.session_key_fingerprint),
      challenge_expires_at: stringOrNull(bundle?.challenge?.expires_at)
    };
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
      if (heldInputError) return fail(heldInputError?.message || 'AML_CHALLENGE_INVALID');
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
      verified: checks.verifier_held_challenge === true,
      ...decide(true, checks.verifier_held_challenge === true),
      reason: 'AML_WITNESS_BUNDLE_VALID',
      checks: { ...checks },
      inspected: { ...inspected },
      ...timing,
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
