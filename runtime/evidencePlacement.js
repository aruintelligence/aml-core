// Simulate one declared failure domain at a time. Labels are operator claims;
// no program can prove that a share was stored at the declared location.
import crypto from "node:crypto";
import { canonicalJSONStringify } from "../protocol/canonicalJson.js";
import { runEvidenceDrill } from "./evidenceDrill.js";
import { recoverEvidenceShards } from "./evidenceShards.js";

const PROTOCOL = "aml-evidence-placement-assessment/1";
const BOUNDARY = "A local simulation over operator-declared failure domains and supplied share files. It does not verify physical placement, custody, independence, or future availability.";
const DIMENSIONS = ["site", "infrastructure", "custodian"];
const sha256 = value => crypto.createHash("sha256").update(canonicalJSONStringify(value)).digest("hex");
const validLabel = value => typeof value === "string" && value.trim() === value && Array.from(value).length > 0 &&
  Array.from(value).length <= 128 && !/[\u0000-\u001f\u007f]/.test(value);

export function assessEvidencePlacement(shares, trustedPolicy, placement) {
  const base = { protocol: PROTOCOL, claim_boundary: BOUNDARY, ready: false,
    health: "invalid", policy_hint_trusted: false, placement_sha256: null,
    drill_health: null, scenarios: [], failed_scenarios: 0 };
  if (!Array.isArray(placement?.shares) || placement.shares.length !== 3 ||
      Object.keys(placement).sort().join("|") !== "protocol|shares" ||
      placement.protocol !== "aml-evidence-placement/1" ||
      placement.shares.some((item, index) => !item || typeof item !== "object" || Array.isArray(item) ||
        Object.keys(item).sort().join("|") !== "custodian|index|infrastructure|site" ||
        item.index !== index || DIMENSIONS.some(dimension => !validLabel(item[dimension])))) {
    return { ...base, reason: "invalid_placement_manifest" };
  }
  const drill = runEvidenceDrill(shares, trustedPolicy);
  const report = { ...base, placement_sha256: sha256(placement),
    drill_health: drill.health, policy_sha256: drill.policy_sha256,
    payload_sha512: drill.subject?.payload_sha512 ?? null };
  if (!drill.recovery_possible) return { ...report, health: "unrecoverable", reason: "baseline_recovery_failed" };
  for (const dimension of DIMENSIONS) {
    const values = [...new Set(placement.shares.map(item => item[dimension]))].sort();
    for (const value of values) {
      const survivingIndices = placement.shares.filter(item => item[dimension] !== value).map(item => item.index);
      const recovery = survivingIndices.length >= 2 ? recoverEvidenceShards(survivingIndices.map(index => shares[index]), trustedPolicy) : null;
      const recovered = recovery?.recovered === true && recovery.payload_sha512 === report.payload_sha512;
      report.scenarios.push({ dimension, value, lost_indices: placement.shares.filter(item => item[dimension] === value).map(item => item.index),
        surviving_indices: survivingIndices, recovered,
        reason: recovered ? null : survivingIndices.length < 2 ? "fewer_than_two_survivors" : recovery?.reason ?? "subject_mismatch" });
    }
  }
  report.failed_scenarios = report.scenarios.filter(scenario => !scenario.recovered).length;
  if (report.failed_scenarios) return { ...report, health: "correlated", reason: "single_domain_loss_breaks_recovery" };
  if (!drill.ready) return { ...report, health: "unverified", reason: "baseline_drill_not_ready" };
  return { ...report, ready: true, health: "declared_resilient", reason: null };
}
