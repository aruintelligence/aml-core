// ĀML key-distinct signed verification quorum — SHIPPED reference prototype.
// Requires valid signed reports over one exact artifact and counts distinct verifier-key fingerprints.
// Distinct keys do not prove distinct people, organizations, independence, or correctness.

import { verifySignedVerificationReport } from './aml-signed-verification-report.js';

export async function createSignedVerificationQuorum(signedReports, { threshold = 2 } = {}) {
  if (!Array.isArray(signedReports) || signedReports.length === 0) throw new Error('AML_SIGNED_QUORUM_REPORTS_REQUIRED');
  if (!Number.isInteger(threshold) || threshold < 1) throw new Error('AML_SIGNED_QUORUM_THRESHOLD_INVALID');

  const checks = [];
  for (const envelope of signedReports) {
    const signature = await verifySignedVerificationReport(envelope);
    checks.push({ envelope, signature });
  }

  const structurallyValid = checks.filter(({ envelope, signature }) =>
    signature.valid &&
    envelope?.report?.schema === 'aml-verification-report/1' &&
    envelope.report.artifact_hash
  );

  if (!structurallyValid.length) throw new Error('AML_SIGNED_QUORUM_NO_VALID_SIGNED_REPORTS');

  const artifactType = structurallyValid[0].envelope.report.artifact_type;
  const artifactHash = structurallyValid[0].envelope.report.artifact_hash;

  for (const { envelope } of structurallyValid) {
    if (envelope.report.artifact_type !== artifactType) throw new Error('AML_SIGNED_QUORUM_ARTIFACT_TYPE_MISMATCH');
    if (envelope.report.artifact_hash !== artifactHash) throw new Error('AML_SIGNED_QUORUM_ARTIFACT_HASH_MISMATCH');
  }

  const validKeyFingerprints = new Set();
  let validReports = 0;
  let invalidReports = 0;
  const reasons = new Set();

  for (const { envelope, signature } of checks) {
    if (!signature.valid) {
      invalidReports += 1;
      reasons.add(signature.reason);
      continue;
    }
    validKeyFingerprints.add(envelope.verifier_key_fingerprint);
    if (envelope.report.valid) validReports += 1;
    else {
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
      distinct_keys: validKeyFingerprints.size,
      valid_signatures: checks.filter(({ signature }) => signature.valid).length,
      valid_reports: validReports,
      invalid_reports: invalidReports,
      threshold_met: validReports >= threshold && validKeyFingerprints.size >= threshold,
      unanimous: invalidReports === 0 && validReports === signedReports.length,
      disagreement_reasons: [...reasons]
    },
    claim_boundary: 'Threshold agreement means enough supplied reports were validly signed by distinct public-key fingerprints over the same exact artifact and reported valid. Distinct keys do not prove distinct people, organizations, independence, authorization, certification, or correctness.'
  };
}
