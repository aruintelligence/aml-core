// compiler/semanticRisk.js
// ĀML v1.3 — classify semantic changes by accountability significance.

import { semanticDiff } from "./semanticDiff.js";

const HIGH_RISK_FIELDS = new Set([
  "purpose",
  "consent_required",
  "collects_personal_data",
  "attention_cost",
  "restoration_value",
  "motion_required",
  "contrast_safe",
  "cognitive_load"
]);

const MEDIUM_RISK_FIELDS = new Set([
  "user_effect",
  "memory_role",
  "reduced_motion_alternative"
]);

function scoreChanges(change) {
  const fields = [
    ...Object.keys(change.property_changes || {}),
    ...Object.keys(change.meaning_changes || {}),
    ...Object.keys(change.structural_changes || {})
  ];
  let score = 0;
  const reasons = [];
  for (const field of fields) {
    if (HIGH_RISK_FIELDS.has(field)) {
      score += 3;
      reasons.push(`${field}:high`);
    } else if (MEDIUM_RISK_FIELDS.has(field)) {
      score += 2;
      reasons.push(`${field}:medium`);
    } else {
      score += 1;
      reasons.push(`${field}:low`);
    }
  }
  return { score, reasons };
}

export function semanticRiskDiff(leftSource, rightSource, options = {}) {
  const diff = semanticDiff(leftSource, rightSource, options);
  const changed = diff.changed.map(change => {
    const { score, reasons } = scoreChanges(change);
    const risk = score >= 6 ? "high" : score >= 3 ? "medium" : "low";
    return { ...change, risk_score: score, risk, risk_reasons: reasons };
  });

  const added = diff.added.map(node => ({ ...node, risk: "medium", risk_score: 3, risk_reasons: ["meaning-bearing node added"] }));
  const removed = diff.removed.map(node => ({ ...node, risk: "high", risk_score: 6, risk_reasons: ["meaning-bearing node removed"] }));
  const all = [...changed, ...added, ...removed];

  return {
    protocol: "ĀML Semantic Risk Diff",
    version: "1.0",
    summary: {
      ...diff.summary,
      high_risk: all.filter(item => item.risk === "high").length,
      medium_risk: all.filter(item => item.risk === "medium").length,
      low_risk: all.filter(item => item.risk === "low").length
    },
    changed,
    added,
    removed,
    unchanged: diff.unchanged
  };
}
