// runtime/policyComposition.js
// ĀML v1.2 — compose multiple policy engines into one accountable decision.

import { resolvePolicy } from "./policyEngine.js";
import { resolvePolicyProfile } from "./policyProfiles.js";

export function composePolicies(policyIds, options = {}) {
  if (!Array.isArray(policyIds) || policyIds.length === 0) {
    throw new Error("composePolicies requires at least one policy.");
  }

  const policies = policyIds.map(resolvePolicy);
  const strategy = options.strategy || "all_must_allow";

  return {
    id: options.id || `composed:${policyIds.join("+")}`,
    description: options.description || `Composed ĀML policy (${strategy}).`,
    evaluate(element, context = {}) {
      const results = policies.map(policy => policy.evaluate(element, context));
      const allowed = strategy === "any_may_allow"
        ? results.some(result => result.render_allowed)
        : results.every(result => result.render_allowed);

      return {
        policy_id: options.id || `composed:${policyIds.join("+")}`,
        policy_strategy: strategy,
        render_allowed: allowed,
        fallback_triggered: !allowed,
        attention_cost: results[0]?.attention_cost ?? 0,
        restoration_value: results[0]?.restoration_value ?? 0,
        calculated_attention_cost: results[0]?.calculated_attention_cost ?? 0,
        calculated_restoration_value: results[0]?.calculated_restoration_value ?? 0,
        rationale: results.map(result => ({
          policy_id: result.policy_id,
          render_allowed: result.render_allowed,
          rationale: result.rationale
        })),
        component_results: results
      };
    }
  };
}

export function policyFromProfile(profile, options = {}) {
  const resolved = resolvePolicyProfile(profile);
  return composePolicies(resolved.policies, {
    id: `profile:${resolved.id}`,
    description: resolved.description,
    strategy: options.strategy || "all_must_allow"
  });
}
