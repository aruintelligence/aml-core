// ĀML verification quorum — SHIPPED reference prototype.
// Aggregates multiple aml-verification-report/1 objects over one exact artifact hash.
// Distinct verifier IDs are only declared identifiers. This module does not prove institutional independence.

import { canonicalJSONStringifyBrowser, snapshotBrowserJSON } from './aml-browser-integrity.js';

export function createVerificationQuorum(reports, { threshold = 2 } = {}) {
  if (!Array.isArray(reports) || reports.length === 0) throw new Error('AML_QUORUM_REPORTS_REQUIRED');
  if (reports.length > 64) throw new Error('AML_QUORUM_TOO_MANY_REPORTS');
  if (!Number.isSafeInteger(threshold) || threshold < 1) throw new Error('AML_QUORUM_THRESHOLD_INVALID');
  // Keep the saved quorum independent of later edits to the caller's reports.
  // Ordinary JSON is also required so the saved object cannot omit live fields.
  reports = snapshotBrowserJSON(reports);

  const normalized = reports.map((report) => {
    if (!report || report.schema !== 'aml-verification-report/1' || report.prototype !== true) {
      throw new Error('AML_QUORUM_REPORT_INVALID');
    }
    if (typeof report.verifier !== 'string' || !report.verifier.trim()) throw new Error('AML_QUORUM_VERIFIER_REQUIRED');
    if (typeof report.artifact_type !== 'string' || !report.artifact_type.trim()) throw new Error('AML_QUORUM_ARTIFACT_TYPE_REQUIRED');
    if (typeof report.artifact_hash !== 'string' || !report.artifact_hash.trim()) throw new Error('AML_QUORUM_ARTIFACT_HASH_REQUIRED');
    if (typeof report.valid !== 'boolean') throw new Error('AML_QUORUM_REPORT_VERDICT_INVALID');
    if (typeof report.reason !== 'string' || !report.reason.trim()) throw new Error('AML_QUORUM_REPORT_REASON_INVALID');
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
    if (!quorum) return { valid: false, reason: 'AML_QUORUM_INVALID', threshold_met: false };
    quorum = snapshotBrowserJSON(quorum);
    if (!quorum || quorum.schema !== 'aml-verification-quorum/1') {
      return { valid: false, reason: 'AML_QUORUM_INVALID', threshold_met: false };
    }
    const rebuilt = createVerificationQuorum(quorum.reports, { threshold: quorum.threshold });
    // Recheck the complete envelope, including prototype, claim boundary, and
    // every summary field. This is structural consistency, not authentication
    // of the reports: an unsigned producer can always rebuild a new quorum.
    const valid = canonicalJSONStringifyBrowser(quorum) === canonicalJSONStringifyBrowser(rebuilt);
    const summaryMatches = quorum.summary !== undefined &&
      canonicalJSONStringifyBrowser(quorum.summary) ===
      canonicalJSONStringifyBrowser(rebuilt.summary);
    return {
      valid,
      reason: valid ? 'AML_QUORUM_VALID' : summaryMatches ?
        'AML_QUORUM_MISMATCH' : 'AML_QUORUM_SUMMARY_MISMATCH',
      threshold_met: valid && rebuilt.summary.threshold_met,
      quorum: rebuilt
    };
  } catch (error) {
    return { valid: false, reason: error?.message || 'AML_QUORUM_VERIFY_ERROR', threshold_met: false };
  }
}
