// ĀML key-distinct signed verification quorum — SHIPPED reference prototype.
// Requires valid signed reports over one exact artifact and counts distinct verifier-key fingerprints.
// Distinct keys do not prove distinct people, organizations, independence, or correctness.

import { assertBrowserJSON, canonicalJSONStringifyBrowser } from './aml-browser-integrity.js';
import { verifySignedVerificationReport } from './aml-signed-verification-report.js';

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
  const validEndorserKeyFingerprints = new Set();
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
      validEndorserKeyFingerprints.add(envelope.verifier_key_fingerprint);
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
      distinct_keys: validEndorserKeyFingerprints.size,
      valid_signatures: checks.filter(({ signature }) => signature.valid).length,
      valid_reports: validReports,
      invalid_reports: invalidReports,
      threshold_met: validReports >= threshold && validEndorserKeyFingerprints.size >= threshold,
      unanimous: invalidReports === 0 && validReports === signedReports.length,
      disagreement_reasons: [...reasons]
    },
    claim_boundary: 'Threshold agreement means enough supplied reports were validly signed by distinct public-key fingerprints over the same exact artifact and reported valid. Correctly signed invalid reports are authenticated dissent and never count toward the endorsement quorum. Distinct keys do not prove distinct people, organizations, independence, authorization, certification, or correctness.'
  };
}

export async function verifySignedVerificationQuorum(quorum) {
  try {
    assertBrowserJSON(quorum);
    if (!quorum || quorum.schema !== 'aml-signed-verification-quorum/1') {
      return { valid: false, reason: 'AML_SIGNED_QUORUM_INVALID', threshold_met: false };
    }
    const rebuilt = await createSignedVerificationQuorum(quorum.signed_reports, { threshold: quorum.threshold });
    const valid = canonicalJSONStringifyBrowser(quorum) === canonicalJSONStringifyBrowser(rebuilt);
    return {
      valid,
      reason: valid ? 'AML_SIGNED_QUORUM_VALID' : 'AML_SIGNED_QUORUM_MISMATCH',
      threshold_met: valid && rebuilt.summary.threshold_met,
      quorum: rebuilt
    };
  } catch (error) {
    return { valid: false, reason: error?.message || 'AML_SIGNED_QUORUM_VERIFY_ERROR', threshold_met: false };
  }
}
