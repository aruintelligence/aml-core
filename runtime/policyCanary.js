// runtime/policyCanary.js
// Compare the same interface intent under a baseline and candidate policy profile.
// This reports decision changes; it does not label either policy morally correct.

import { createInterfaceFirewall } from "./interfaceFirewall.js";
import { buildPairedComparisonIndexes } from "./comparisonIdentity.js";

function decisionKey(decision, index) {
  return decision.identifier ?? decision.id ?? decision.node_id ?? decision.name ?? `index:${index}`;
}

export function evaluatePolicyCanary(intent, options = {}) {
  const baselineProfile = options.baseline_profile || "calm_default";
  const candidateProfile = options.candidate_profile || "human_first";
  const context = options.context || {};
  const timestamp = options.timestamp;

  const baseline = createInterfaceFirewall({ profile: baselineProfile, context }).enforce(intent, {
    profile: baselineProfile,
    context,
    timestamp
  });
  const candidate = createInterfaceFirewall({ profile: candidateProfile, context }).enforce(intent, {
    profile: candidateProfile,
    context,
    timestamp
  });

  const paired = buildPairedComparisonIndexes(baseline.decisions, candidate.decisions, decisionKey);
  const baselineByKey = paired.left.index;
  const candidateByKey = paired.right.index;
  const keys = [...new Set([...baselineByKey.keys(), ...candidateByKey.keys()])].sort();

  const changes = keys.map((key) => {
    const before = baselineByKey.get(key) || null;
    const after = candidateByKey.get(key) || null;
    const beforeAllowed = before?.render_allowed ?? null;
    const afterAllowed = after?.render_allowed ?? null;
    return {
      key,
      identity_ambiguous: paired.ambiguous_identity_keys.some(entry => key.startsWith(`${entry.key}#`)),
      baseline_render_allowed: beforeAllowed,
      candidate_render_allowed: afterAllowed,
      changed: beforeAllowed !== afterAllowed,
      baseline: before,
      candidate: after
    };
  });

  const changed = changes.filter(item => item.changed);
  return {
    protocol: "ĀML Policy Canary Result",
    version: "1.0",
    baseline_profile: baselineProfile,
    candidate_profile: candidateProfile,
    ambiguous_identity_keys: paired.ambiguous_identity_keys,
    identity_ambiguity_detected: paired.ambiguous_identity_keys.length > 0,
    total_decisions: changes.length,
    changed_decisions: changed.length,
    candidate_new_suppressions: changed.filter(item => item.baseline_render_allowed === true && item.candidate_render_allowed === false).length,
    candidate_new_allows: changed.filter(item => item.baseline_render_allowed === false && item.candidate_render_allowed === true).length,
    changes,
    baseline: {
      allowed: baseline.allowed,
      denied_count: baseline.denied_count,
      receipt_sha256: baseline.receipt.receipt_sha256,
      receipt: baseline.receipt
    },
    candidate: {
      allowed: candidate.allowed,
      denied_count: candidate.denied_count,
      receipt_sha256: candidate.receipt.receipt_sha256,
      receipt: candidate.receipt
    }
  };
}
