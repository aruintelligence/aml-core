// tooling/prGate.js
// CI-friendly semantic/policy regression gate for AML source changes.

import { semanticRiskDiff } from "../compiler/semanticRisk.js";
import { policyDiff } from "../compiler/policyDiff.js";

export function evaluatePullRequestChange(beforeSource, afterSource, options = {}) {
  const semantic = semanticRiskDiff(beforeSource, afterSource, options);
  const policy = policyDiff(afterSource, options.beforePolicy || "calm_default", options.afterPolicy || "human_first", {
    context: options.context || {},
    timestamp: options.timestamp
  });

  const highRisk = [
    ...(semantic.changed || []),
    ...(semantic.added || []),
    ...(semantic.removed || [])
  ].filter(change => change.risk === "high");

  const policyRegressions = (policy.changes || []).filter(change => {
    const before = change.left?.render_allowed;
    const after = change.right?.render_allowed;
    return before === true && after === false;
  });

  const passed = highRisk.length === 0 && policyRegressions.length === 0;

  return {
    protocol: "ĀML Pull Request Gate",
    version: "1.0",
    passed,
    semantic_risk: semantic,
    policy_diff: policy,
    blocking: {
      high_risk_semantic_changes: highRisk,
      policy_regressions: policyRegressions
    }
  };
}

export function formatPullRequestGate(report) {
  const status = report.passed ? "PASS" : "BLOCK";
  return [
    `ĀML PR Gate: ${status}`,
    `High-risk semantic changes: ${report.blocking.high_risk_semantic_changes.length}`,
    `Policy regressions: ${report.blocking.policy_regressions.length}`
  ].join("\n");
}
