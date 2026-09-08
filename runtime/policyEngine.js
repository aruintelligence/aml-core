// runtime/policyEngine.js
// ĀML v1.3 research surface — pluggable, context-aware rendering policies.

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

function isTrue(value) {
  return value === true || value === "true" || value === "yes" || value === "required";
}

export const BUILTIN_POLICIES = Object.freeze({
  restorative_v1: {
    id: "restorative_v1",
    description: "Allow when restoration value is greater than or equal to attention cost.",
    evaluate(element) {
      const { gate, attention, restoration } = baseMetrics(element);
      const allowed = restoration >= attention;
      return baseResult("restorative_v1", gate, attention, restoration, allowed,
        allowed ? "restoration_value >= attention_cost" : "restoration_value < attention_cost");
    }
  },
  attention_conservative_v1: {
    id: "attention_conservative_v1",
    description: "Require restoration value to exceed attention cost by at least 20 percent.",
    evaluate(element) {
      const { gate, attention, restoration } = baseMetrics(element);
      const threshold = attention * 1.2;
      const allowed = restoration >= threshold;
      return baseResult("attention_conservative_v1", gate, attention, restoration, allowed,
        `restoration_value >= attention_cost * 1.2 (threshold=${threshold})`);
    }
  },
  consent_guard_v1: {
    id: "consent_guard_v1",
    description: "Apply the restorative rule, but suppress consent-gated nodes unless runtime context grants consent.",
    evaluate(element, execution = {}) {
      const { gate, attention, restoration } = baseMetrics(element);
      const consentRequired = isTrue(execution.node?.properties?.consent_required);
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
      const collectsPersonalData = isTrue(execution.node?.properties?.collects_personal_data);
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
  },
  reduced_motion_v1: {
    id: "reduced_motion_v1",
    description: "Suppress motion-required nodes when runtime context indicates a reduced-motion preference unless an accessible non-motion alternative is declared.",
    evaluate(element, execution = {}) {
      const { gate, attention, restoration } = baseMetrics(element);
      const prefersReducedMotion = execution.context?.prefers_reduced_motion === true;
      const motionRequired = isTrue(execution.node?.properties?.motion_required);
      const hasAlternative = isTrue(execution.node?.properties?.reduced_motion_alternative);
      const restorativeAllowed = restoration >= attention;
      const motionAllowed = !prefersReducedMotion || !motionRequired || hasAlternative;
      const allowed = restorativeAllowed && motionAllowed;
      const rationale = !restorativeAllowed
        ? "restoration_value < attention_cost"
        : prefersReducedMotion && motionRequired && !hasAlternative
          ? "runtime prefers_reduced_motion and node requires motion without a reduced-motion alternative"
          : prefersReducedMotion && motionRequired && hasAlternative
            ? "motion-required node declares a reduced-motion alternative"
            : "reduced-motion policy satisfied";
      return baseResult("reduced_motion_v1", gate, attention, restoration, allowed, rationale);
    }
  },
  contrast_safety_v1: {
    id: "contrast_safety_v1",
    description: "Suppress nodes explicitly marked contrast-unsafe when runtime context requires high contrast.",
    evaluate(element, execution = {}) {
      const { gate, attention, restoration } = baseMetrics(element);
      const requiresHighContrast = execution.context?.high_contrast_required === true;
      const contrastUnsafe = execution.node?.properties?.contrast_safe === false || execution.node?.properties?.contrast_safe === "false";
      const restorativeAllowed = restoration >= attention;
      const contrastAllowed = !requiresHighContrast || !contrastUnsafe;
      const allowed = restorativeAllowed && contrastAllowed;
      const rationale = !restorativeAllowed
        ? "restoration_value < attention_cost"
        : requiresHighContrast && contrastUnsafe
          ? "runtime high_contrast_required but node declares contrast_safe=false"
          : "contrast-safety policy satisfied";
      return baseResult("contrast_safety_v1", gate, attention, restoration, allowed, rationale);
    }
  },
  cognitive_load_guard_v1: {
    id: "cognitive_load_guard_v1",
    description: "Suppress nodes whose declared cognitive load exceeds the runtime user's configured maximum.",
    evaluate(element, execution = {}) {
      const { gate, attention, restoration } = baseMetrics(element);
      const rawLoad = execution.node?.properties?.cognitive_load;
      const load = typeof rawLoad === "number" ? rawLoad : attention;
      const max = execution.context?.max_cognitive_load;
      const hasMax = typeof max === "number" && Number.isFinite(max);
      const restorativeAllowed = restoration >= attention;
      const loadAllowed = !hasMax || load <= max;
      const allowed = restorativeAllowed && loadAllowed;
      const rationale = !restorativeAllowed
        ? "restoration_value < attention_cost"
        : hasMax && !loadAllowed
          ? `cognitive_load (${load}) exceeds max_cognitive_load (${max})`
          : hasMax
            ? `cognitive_load (${load}) is within max_cognitive_load (${max})`
            : "no runtime max_cognitive_load supplied";
      return baseResult("cognitive_load_guard_v1", gate, attention, restoration, allowed, rationale);
    }
  }
});

export function resolvePolicy(policy = "restorative_v1") {
  if (typeof policy === "function") return { id: "custom", evaluate: policy };
  if (policy && typeof policy.evaluate === "function") return { id: policy.id || "custom", evaluate: policy.evaluate.bind(policy) };
  if (typeof policy === "string" && BUILTIN_POLICIES[policy]) return BUILTIN_POLICIES[policy];
  throw new Error(`Unknown ĀML policy engine: ${String(policy)}`);
}

export function listPolicies() {
  return Object.values(BUILTIN_POLICIES).map(({ id, description }) => ({ id, description }));
}
