// runtime/policyCanary.js
// Compare the same interface intent under a baseline and candidate policy profile.
// This reports decision changes; it does not label either policy morally correct.

import { createInterfaceFirewall } from "./interfaceFirewall.js";

function decisionKey(decision, index) {
  return decision.identifier ?? decision.id ?? decision.node_id ?? `index:${index}`;
}

function indexDecisions(decisions) {
  return new Map(decisions.map((decision, index) => [decisionKey(decision, index), decision]));
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

  const baselineByKey = indexDecisions(baseline.decisions);
  const candidateByKey = indexDecisions(candidate.decisions);
  const keys = [...new Set([...baselineByKey.keys(), ...candidateByKey.keys()])];

  const changes = keys.map((key) => {
    const before = baselineByKey.get(key) || null;
    const after = candidateByKey.get(key) || null;
    const beforeAllowed = before?.render_allowed ?? null;
    const afterAllowed = after?.render_allowed ?? null;
    return {
      key,
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
