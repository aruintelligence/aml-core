// runtime/policyEngine.js
// ĀML v1.2 research surface — pluggable rendering policy engines.

import { ethicalRenderGate } from "./ethicalRenderGate.js";

export const BUILTIN_POLICIES = Object.freeze({
  restorative_v1: {
    id: "restorative_v1",
    description: "Allow when restoration value is greater than or equal to attention cost.",
    evaluate(element) {
      const gate = ethicalRenderGate(element);
      const attention = typeof element.attention_cost === "number" ? element.attention_cost : gate.attention_cost;
      const restoration = typeof element.restoration_value === "number" ? element.restoration_value : gate.restoration_value;
      return {
        policy_id: "restorative_v1",
        attention_cost: attention,
        restoration_value: restoration,
        render_allowed: restoration >= attention,
        fallback_triggered: restoration < attention,
        calculated_attention_cost: gate.attention_cost,
        calculated_restoration_value: gate.restoration_value,
        rationale: restoration >= attention
          ? "restoration_value >= attention_cost"
          : "restoration_value < attention_cost"
      };
    }
  },
  attention_conservative_v1: {
    id: "attention_conservative_v1",
    description: "Require restoration value to exceed attention cost by at least 20 percent.",
    evaluate(element) {
      const gate = ethicalRenderGate(element);
      const attention = typeof element.attention_cost === "number" ? element.attention_cost : gate.attention_cost;
      const restoration = typeof element.restoration_value === "number" ? element.restoration_value : gate.restoration_value;
      const threshold = attention * 1.2;
      return {
        policy_id: "attention_conservative_v1",
        attention_cost: attention,
        restoration_value: restoration,
        render_allowed: restoration >= threshold,
        fallback_triggered: restoration < threshold,
        calculated_attention_cost: gate.attention_cost,
        calculated_restoration_value: gate.restoration_value,
        rationale: `restoration_value >= attention_cost * 1.2 (threshold=${threshold})`
      };
    }
  }
});

export function resolvePolicy(policy = "restorative_v1") {
  if (typeof policy === "function") {
    return { id: "custom", evaluate: policy };
  }
  if (policy && typeof policy.evaluate === "function") {
    return { id: policy.id || "custom", evaluate: policy.evaluate.bind(policy) };
  }
  if (typeof policy === "string" && BUILTIN_POLICIES[policy]) {
    return BUILTIN_POLICIES[policy];
  }
  throw new Error(`Unknown ĀML policy engine: ${String(policy)}`);
}

export function listPolicies() {
  return Object.values(BUILTIN_POLICIES).map(({ id, description }) => ({ id, description }));
}
