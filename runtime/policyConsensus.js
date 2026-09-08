// runtime/policyConsensus.js
// ĀML v1.3 — multi-policy consensus with explicit dissent.

import { resolvePolicy } from "./policyEngine.js";

export function createPolicyConsensus(policyIds, options = {}) {
  if (!Array.isArray(policyIds) || policyIds.length === 0) throw new Error("Policy consensus requires at least one policy.");
  const members = policyIds.map(id => resolvePolicy(id));
  const strategy = options.strategy || "majority";
  const weights = options.weights || {};

  return {
    id: options.id || `consensus:${strategy}:${policyIds.join("+")}`,
    description: options.description || `ĀML policy consensus (${strategy}).`,
    evaluate(element, execution = {}) {
      const votes = members.map(policy => {
        const result = policy.evaluate(element, execution);
        const weight = Number.isFinite(weights[policy.id]) ? weights[policy.id] : 1;
        return {
          policy_id: policy.id,
          render_allowed: result.render_allowed,
          rationale: result.rationale,
          weight
        };
      });

      const totalWeight = votes.reduce((sum, vote) => sum + vote.weight, 0);
      const allowWeight = votes.filter(vote => vote.render_allowed).reduce((sum, vote) => sum + vote.weight, 0);
      const denyWeight = totalWeight - allowWeight;
      let allowed;
      if (strategy === "unanimous") allowed = denyWeight === 0;
      else if (strategy === "any") allowed = allowWeight > 0;
      else allowed = allowWeight > denyWeight;

      const dissent = votes.filter(vote => vote.render_allowed !== allowed);
      return {
        policy_id: options.id || `consensus:${strategy}:${policyIds.join("+")}`,
        policy_strategy: strategy,
        render_allowed: allowed,
        fallback_triggered: !allowed,
        attention_cost: execution?.base_result?.attention_cost ?? element.attention_cost ?? 0,
        restoration_value: execution?.base_result?.restoration_value ?? element.restoration_value ?? 0,
        rationale: {
          allow_weight: allowWeight,
          deny_weight: denyWeight,
          total_weight: totalWeight,
          dissent_count: dissent.length
        },
        votes,
        dissent
      };
    }
  };
}
