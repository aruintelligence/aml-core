// runtime/policyEngine.js
// ĀML v1.2 research surface — pluggable, context-aware rendering policies.

import { ethicalRenderGate } from "./ethicalRenderGate.js";

function baseMetrics(element) {
  const gate = ethicalRenderGate(element);
  const attention = typeof element.attention_cost === "number" ? element.attention_cost : gate.attention_cost;
  const restoration = typeof element.restoration_value === "number" ? element.restoration_value : gate.restoration_value;
  return { gate, attention, restoration };
}

function baseResult(policyId, gate, attention, restoration, allowed, rationale) {
  return {
    policy_id: policyId,
    attention_cost: attention,
    restoration_value: restoration,
    render_allowed: allowed,
    fallback_triggered: !allowed,
    calculated_attention_cost: gate.attention_cost,
    calculated_restoration_value: gate.restoration_value,
    rationale
  };
}

export const BUILTIN_POLICIES = Object.freeze({
  restorative_v1: {
    id: "restorative_v1",
    description: "Allow when restoration value is greater than or equal to attention cost.",
    evaluate(element) {
      const { gate, attention, restoration } = baseMetrics(element);
      const allowed = restoration >= attention;
      return baseResult(
        "restorative_v1",
        gate,
        attention,
        restoration,
        allowed,
        allowed ? "restoration_value >= attention_cost" : "restoration_value < attention_cost"
      );
    }
  },
  attention_conservative_v1: {
    id: "attention_conservative_v1",
    description: "Require restoration value to exceed attention cost by at least 20 percent.",
    evaluate(element) {
      const { gate, attention, restoration } = baseMetrics(element);
      const threshold = attention * 1.2;
      const allowed = restoration >= threshold;
      return baseResult(
        "attention_conservative_v1",
        gate,
        attention,
        restoration,
        allowed,
        `restoration_value >= attention_cost * 1.2 (threshold=${threshold})`
      );
    }
  },
  consent_guard_v1: {
    id: "consent_guard_v1",
    description: "Apply the restorative rule, but suppress consent-gated nodes unless runtime context grants consent.",
    evaluate(element, execution = {}) {
      const { gate, attention, restoration } = baseMetrics(element);
      const rawRequirement = execution.node?.properties?.consent_required;
      const consentRequired = rawRequirement === true || rawRequirement === "true" || rawRequirement === "required" || rawRequirement === "yes";
      const consentGranted = execution.context?.consent_granted === true;
      const restorativeAllowed = restoration >= attention;
      const allowed = restorativeAllowed && (!consentRequired || consentGranted);
      const rationale = !restorativeAllowed
        ? "restoration_value < attention_cost"
        : consentRequired && !consentGranted
          ? "consent_required but runtime consent_granted != true"
          : consentRequired
            ? "consent_required and runtime consent_granted == true"
            : "no consent gate and restoration_value >= attention_cost";
      return baseResult("consent_guard_v1", gate, attention, restoration, allowed, rationale);
    }
  },
  privacy_guard_v1: {
    id: "privacy_guard_v1",
    description: "Suppress nodes declaring personal-data collection unless runtime privacy consent is granted.",
    evaluate(element, execution = {}) {
      const { gate, attention, restoration } = baseMetrics(element);
      const rawCollection = execution.node?.properties?.collects_personal_data;
      const collectsPersonalData = rawCollection === true || rawCollection === "true" || rawCollection === "yes" || rawCollection === "required";
      const privacyConsent = execution.context?.privacy_consent === true;
      const restorativeAllowed = restoration >= attention;
      const allowed = restorativeAllowed && (!collectsPersonalData || privacyConsent);
      const rationale = !restorativeAllowed
        ? "restoration_value < attention_cost"
        : collectsPersonalData && !privacyConsent
          ? "collects_personal_data but runtime privacy_consent != true"
          : collectsPersonalData
            ? "personal-data collection permitted by runtime privacy consent"
            : "no personal-data collection declared";
      return baseResult("privacy_guard_v1", gate, attention, restoration, allowed, rationale);
    }
  },
  session_attention_budget_v1: {
    id: "session_attention_budget_v1",
    description: "Suppress a node when its declared/calculated attention cost exceeds the runtime session attention budget remaining.",
    evaluate(element, execution = {}) {
      const { gate, attention, restoration } = baseMetrics(element);
      const budget = execution.context?.attention_budget_remaining;
      const hasBudget = typeof budget === "number" && Number.isFinite(budget);
      const restorativeAllowed = restoration >= attention;
      const budgetAllowed = !hasBudget || attention <= budget;
      const allowed = restorativeAllowed && budgetAllowed;
      const rationale = !restorativeAllowed
        ? "restoration_value < attention_cost"
        : hasBudget && !budgetAllowed
          ? `attention_cost (${attention}) exceeds attention_budget_remaining (${budget})`
          : hasBudget
            ? `attention_cost (${attention}) is within attention_budget_remaining (${budget})`
            : "no runtime attention budget supplied";
      return baseResult("session_attention_budget_v1", gate, attention, restoration, allowed, rationale);
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
