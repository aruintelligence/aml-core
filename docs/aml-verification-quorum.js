// ĀML verification quorum — SHIPPED reference prototype.
// Aggregates multiple aml-verification-report/1 objects over one exact artifact hash.
// Distinct verifier IDs are only declared identifiers. This module does not prove institutional independence.

export function createVerificationQuorum(reports, { threshold = 2 } = {}) {
  if (!Array.isArray(reports) || reports.length === 0) throw new Error('AML_QUORUM_REPORTS_REQUIRED');
  if (!Number.isInteger(threshold) || threshold < 1) throw new Error('AML_QUORUM_THRESHOLD_INVALID');

  const normalized = reports.map((report) => {
    if (!report || report.schema !== 'aml-verification-report/1') throw new Error('AML_QUORUM_REPORT_INVALID');
    if (!report.verifier) throw new Error('AML_QUORUM_VERIFIER_REQUIRED');
    if (!report.artifact_type) throw new Error('AML_QUORUM_ARTIFACT_TYPE_REQUIRED');
    if (!report.artifact_hash) throw new Error('AML_QUORUM_ARTIFACT_HASH_REQUIRED');
    return report;
  });

  const artifactType = normalized[0].artifact_type;
  const artifactHash = normalized[0].artifact_hash;
  for (const report of normalized) {
    if (report.artifact_type !== artifactType) throw new Error('AML_QUORUM_ARTIFACT_TYPE_MISMATCH');
    if (report.artifact_hash !== artifactHash) throw new Error('AML_QUORUM_ARTIFACT_HASH_MISMATCH');
  }

  const byVerifier = new Map();
  for (const report of normalized) {
    if (byVerifier.has(report.verifier)) throw new Error('AML_QUORUM_DUPLICATE_VERIFIER');
    byVerifier.set(report.verifier, report);
  }

  const validReports = normalized.filter((report) => report.valid).length;
  const invalidReports = normalized.length - validReports;
  const reasons = [...new Set(normalized.filter((report) => !report.valid).map((report) => report.reason))];

  return {
    schema: 'aml-verification-quorum/1',
    prototype: true,
    artifact_type: artifactType,
    artifact_hash: artifactHash,
    threshold,
    reports: normalized,
    summary: {
      distinct_verifiers: byVerifier.size,
      valid_reports: validReports,
      invalid_reports: invalidReports,
      threshold_met: validReports >= threshold,
      unanimous: validReports === normalized.length,
      disagreement_reasons: reasons
    },
    claim_boundary: 'Threshold agreement means the supplied distinct verifier identifiers reported compatible results over the same artifact. It does not prove verifier independence, correctness, identity, authorization, or truth of the underlying AML declarations.'
  };
}

export function verifyVerificationQuorum(quorum) {
  try {
    if (!quorum || quorum.schema !== 'aml-verification-quorum/1') return { valid: false, reason: 'AML_QUORUM_INVALID' };
    const rebuilt = createVerificationQuorum(quorum.reports, { threshold: quorum.threshold });
    const valid =
      rebuilt.artifact_type === quorum.artifact_type &&
      rebuilt.artifact_hash === quorum.artifact_hash &&
      JSON.stringify(rebuilt.summary) === JSON.stringify(quorum.summary);
    return { valid, reason: valid ? 'AML_QUORUM_VALID' : 'AML_QUORUM_SUMMARY_MISMATCH', quorum: rebuilt };
  } catch (error) {
    return { valid: false, reason: error?.message || 'AML_QUORUM_VERIFY_ERROR' };
  }
}
