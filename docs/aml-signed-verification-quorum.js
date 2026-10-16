// ĀML key-distinct signed verification quorum — SHIPPED reference prototype.
// Requires valid signed reports over one exact artifact and counts distinct P-256 public keys.
// Distinct keys do not prove distinct people, organizations, independence, or correctness.

import { assertBrowserJSON, canonicalJSONStringifyBrowser } from './aml-browser-integrity.js';
import { verifySignedVerificationReport } from './aml-signed-verification-report.js';

// Envelope fingerprints bind the complete JWK JSON, including optional metadata.
// For quorum identity, hash the P-256 public point instead: one key must count once
// even when the same JWK carries different labels, key_ops, or other metadata.
async function verifierKeyMaterialFingerprint(jwk) {
  if (!jwk || jwk.kty !== 'EC' || jwk.crv !== 'P-256' ||
      typeof jwk.x !== 'string' || typeof jwk.y !== 'string') {
    throw new Error('AML_SIGNED_QUORUM_KEY_MATERIAL_INVALID');
  }
  const decode = value => Uint8Array.from(atob(value.replace(/-/g, '+').replace(/_/g, '/')),
    character => character.charCodeAt(0));
  const x = decode(jwk.x);
  const y = decode(jwk.y);
  if (x.length !== 32 || y.length !== 32) throw new Error('AML_SIGNED_QUORUM_KEY_MATERIAL_INVALID');
  const rawPoint = new Uint8Array(65);
  rawPoint[0] = 4;
  rawPoint.set(x, 1);
  rawPoint.set(y, 33);
  const digest = await crypto.subtle.digest('SHA-256', rawPoint);
  return [...new Uint8Array(digest)].map(byte => byte.toString(16).padStart(2, '0')).join('');
}

export async function createSignedVerificationQuorum(signedReports, { threshold = 2 } = {}) {
  if (!Array.isArray(signedReports) || signedReports.length === 0) throw new Error('AML_SIGNED_QUORUM_REPORTS_REQUIRED');
  if (signedReports.length > 64) throw new Error('AML_SIGNED_QUORUM_TOO_MANY_REPORTS');
  if (!Number.isInteger(threshold) || threshold < 1) throw new Error('AML_SIGNED_QUORUM_THRESHOLD_INVALID');
  assertBrowserJSON(signedReports);

  const checks = [];
  for (const envelope of signedReports) {
    const signature = await verifySignedVerificationReport(envelope);
    checks.push({ envelope, signature });
  }

  const signed = checks.filter(({ signature }) => signature.valid);
  if (!signed.length) throw new Error('AML_SIGNED_QUORUM_NO_VALID_SIGNED_REPORTS');

  // Every authenticated report must identify the same artifact and carry a
  // boolean verdict. A signature over malformed metadata is not an endorsement.
  for (const { envelope } of signed) {
    const report = envelope.report;
    if (report.prototype !== true || typeof report.verifier !== 'string' || !report.verifier.trim()) {
      throw new Error('AML_SIGNED_QUORUM_REPORT_INVALID');
    }
    if (typeof report.artifact_type !== 'string' || !report.artifact_type.trim()) {
      throw new Error('AML_SIGNED_QUORUM_ARTIFACT_TYPE_REQUIRED');
    }
    if (typeof report.artifact_hash !== 'string' || !report.artifact_hash.trim()) {
      throw new Error('AML_SIGNED_QUORUM_ARTIFACT_HASH_REQUIRED');
    }
    if (typeof report.valid !== 'boolean') {
      throw new Error('AML_SIGNED_QUORUM_REPORT_VERDICT_INVALID');
    }
    if (typeof report.reason !== 'string' || !report.reason.trim()) {
      throw new Error('AML_SIGNED_QUORUM_REPORT_REASON_INVALID');
    }
  }

  const artifactType = signed[0].envelope.report.artifact_type;
  const artifactHash = signed[0].envelope.report.artifact_hash;

  for (const { envelope } of signed) {
    if (envelope.report.artifact_type !== artifactType) throw new Error('AML_SIGNED_QUORUM_ARTIFACT_TYPE_MISMATCH');
    if (envelope.report.artifact_hash !== artifactHash) throw new Error('AML_SIGNED_QUORUM_ARTIFACT_HASH_MISMATCH');
  }

  // Only keys that signed a valid verdict count toward the endorsement quorum.
  // A correctly signed INVALID report is authenticated dissent, not support.
  const validEndorserKeys = new Set();
  let validReports = 0;
  let invalidReports = 0;
  const reasons = new Set();

  for (const { envelope, signature } of checks) {
    if (!signature.valid) {
      invalidReports += 1;
      reasons.add(signature.reason);
      continue;
    }

    if (envelope.report.valid) {
      validReports += 1;
      validEndorserKeys.add(await verifierKeyMaterialFingerprint(envelope.verifier_public_key_jwk));
    } else {
      invalidReports += 1;
      reasons.add(envelope.report.reason);
    }
  }

  return {
    schema: 'aml-signed-verification-quorum/1',
    prototype: true,
    artifact_type: artifactType,
    artifact_hash: artifactHash,
    threshold,
    signed_reports: signedReports,
    summary: {
      distinct_keys: validEndorserKeys.size,
      valid_signatures: checks.filter(({ signature }) => signature.valid).length,
      valid_reports: validReports,
      invalid_reports: invalidReports,
      threshold_met: validReports >= threshold && validEndorserKeys.size >= threshold,
      unanimous: invalidReports === 0 && validReports === signedReports.length,
      disagreement_reasons: [...reasons]
    },
    claim_boundary: 'Threshold agreement means enough supplied reports were validly signed by distinct public-key fingerprints over the same exact artifact and reported valid. Correctly signed invalid reports are authenticated dissent and never count toward the endorsement quorum. Distinct keys do not prove distinct people, organizations, independence, authorization, certification, or correctness.'
  };
}

export function validateSignedVerificationQuorumPolicy(policy) {
  assertBrowserJSON(policy);
  const fields = ['artifact_hash', 'artifact_type', 'prototype', 'schema', 'threshold', 'trusted_key_fingerprints'];
  if (!policy || Array.isArray(policy) || Object.keys(policy).sort().join('|') !== fields.join('|') ||
      policy.schema !== 'aml-signed-quorum-held-policy/1' || policy.prototype !== true) {
    throw new Error('AML_SIGNED_QUORUM_POLICY_INVALID');
  }
  if (typeof policy.artifact_type !== 'string' || !policy.artifact_type.trim() ||
      typeof policy.artifact_hash !== 'string' || !/^[a-f0-9]{64}$/.test(policy.artifact_hash)) {
    throw new Error('AML_SIGNED_QUORUM_POLICY_ARTIFACT_INVALID');
  }
  const keys = policy.trusted_key_fingerprints;
  if (!Array.isArray(keys) || keys.length === 0 || keys.length > 64 ||
      keys.some(key => typeof key !== 'string' || !/^[a-f0-9]{64}$/.test(key)) ||
      new Set(keys).size !== keys.length) {
    throw new Error('AML_SIGNED_QUORUM_POLICY_KEYS_INVALID');
  }
  if (!Number.isInteger(policy.threshold) || policy.threshold < 1 || policy.threshold > keys.length) {
    throw new Error('AML_SIGNED_QUORUM_POLICY_THRESHOLD_INVALID');
  }
  return policy;
}

export async function verifySignedVerificationQuorum(quorum, { policy } = {}) {
  // A verifier-held policy is configuration, not part of the untrusted quorum.
  // Reject malformed configuration as a usage error before checking the quorum.
  if (policy !== undefined) validateSignedVerificationQuorumPolicy(policy);
  const reject = (reason) => ({
    valid: false, reason, threshold_met: false,
    ...(policy === undefined ? {} : { policy_met: false })
  });
  try {
    assertBrowserJSON(quorum);
    if (!quorum || quorum.schema !== 'aml-signed-verification-quorum/1') {
      return reject('AML_SIGNED_QUORUM_INVALID');
    }
    const rebuilt = await createSignedVerificationQuorum(quorum.signed_reports, { threshold: quorum.threshold });
    const valid = canonicalJSONStringifyBrowser(quorum) === canonicalJSONStringifyBrowser(rebuilt);
    const result = {
      valid,
      reason: valid ? 'AML_SIGNED_QUORUM_VALID' : 'AML_SIGNED_QUORUM_MISMATCH',
      threshold_met: valid && rebuilt.summary.threshold_met,
      quorum: rebuilt
    };
    if (policy === undefined) return result;
    if (!valid) return { ...result, policy_met: false };

    const artifactMatches = rebuilt.artifact_type === policy.artifact_type &&
      rebuilt.artifact_hash === policy.artifact_hash;
    const allowed = new Set(policy.trusted_key_fingerprints);
    const trusted = new Set();
    if (artifactMatches) {
      for (const envelope of rebuilt.signed_reports) {
        if (envelope?.report?.valid !== true || !allowed.has(envelope.verifier_key_fingerprint)) continue;
        if ((await verifySignedVerificationReport(envelope)).valid) {
          trusted.add(await verifierKeyMaterialFingerprint(envelope.verifier_public_key_jwk));
        }
      }
    }
    return {
      ...result,
      policy_met: artifactMatches && trusted.size >= policy.threshold,
      policy_evaluation: {
        artifact_matches: artifactMatches,
        distinct_trusted_keys: trusted.size,
        threshold: policy.threshold
      }
    };
  } catch (error) {
    return reject(error?.message || 'AML_SIGNED_QUORUM_VERIFY_ERROR');
  }
}
