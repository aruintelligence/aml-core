// A local rehearsal report. It records what this verifier checked, not when
// history happened or whether the verifier's external policy is authoritative.
import crypto from "node:crypto";
import { canonicalJSONStringify } from "../protocol/canonicalJson.js";
import { recoverEvidenceShards } from "./evidenceShards.js";
import { verifyEvidenceMigration } from "./evidenceMigration.js";

const PROTOCOL = "aml-evidence-recovery-drill/1";
const BOUNDARY = "A project-authored local recovery rehearsal. The external policy and accepted head must be preserved separately; this report is not independent witnessing or a trusted timestamp.";
const PAIRS = [[0, 1], [0, 2], [1, 2]];
const sha256 = value => crypto.createHash("sha256").update(value).digest("hex");

export function runEvidenceDrill(shares, trustedPolicy) {
  const report = {
    protocol: PROTOCOL, claim_boundary: BOUNDARY, ready: false, recovery_possible: false,
    health: "unrecoverable", policy_hint_trusted: false, policy_sha256: null,
    subject: null, passed_pairs: 0, required_pairs: 3, pairs: []
  };
  if (!Array.isArray(shares) || shares.length !== 3) {
    return { ...report, reason: "three_share_slots_required" };
  }
  if (!trustedPolicy || typeof trustedPolicy !== "object" || Array.isArray(trustedPolicy)) {
    return { ...report, reason: "external_trust_required" };
  }
  try {
    report.policy_sha256 = sha256(canonicalJSONStringify(trustedPolicy));
  } catch {
    return { ...report, reason: "invalid_external_policy" };
  }
  const positioned = shares.map((share, index) => share?.index === index ? share : null);
  const recovered = [];
  report.pairs = PAIRS.map(indices => {
    const [a, b] = indices;
    if (!positioned[a] || !positioned[b]) {
      return { shares: indices, recovered: false, reason: "missing_or_misidentified_share" };
    }
    const result = recoverEvidenceShards([positioned[a], positioned[b]], trustedPolicy);
    if (!result.recovered) return { shares: indices, recovered: false, reason: result.reason };
    const verification = verifyEvidenceMigration(result.migration, trustedPolicy);
    recovered.push({ migration: result.migration, digest: result.payload_sha512, verification });
    return { shares: indices, recovered: true, payload_sha512: result.payload_sha512,
      migration_root_sha3_512: result.migration.root_sha3_512 };
  });
  report.passed_pairs = recovered.length;
  report.recovery_possible = recovered.length > 0;
  if (!recovered.length) return { ...report, reason: "no_trusted_recovery_pair" };
  const [first] = recovered;
  if (recovered.some(item => item.digest !== first.digest ||
      item.migration.root_sha3_512 !== first.migration.root_sha3_512)) {
    return { ...report, health: "conflict", reason: "recovery_pairs_disagree" };
  }
  report.subject = {
    payload_sha512: first.digest,
    migration_root_sha3_512: first.migration.root_sha3_512,
    source_archive_root_sha3_512: first.verification.source_archive_root_sha3_512,
    accepted_head_bound: first.verification.freshness_bound === true
  };
  if (recovered.length < 3) return { ...report, health: "degraded", reason: "one_or_more_pairs_failed" };
  if (!report.subject.accepted_head_bound) return { ...report, health: "unbounded", reason: "accepted_head_required_for_drill" };
  return { ...report, ready: true, health: "ready", reason: null };
}
