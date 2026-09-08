// adapters/react.js
// Lightweight React-compatible adapter without taking React as a package dependency.

import { createInterfaceFirewall } from "../runtime/interfaceFirewall.js";

export function evaluateAccountableProps(props = {}, options = {}) {
  const intent = {
    type: props.type || "component",
    id: props.id || "accountable-ui",
    purpose: props.purpose || "",
    content: props.content || "",
    attention_cost: props.attentionCost ?? props.attention_cost ?? 0,
    restoration_value: props.restorationValue ?? props.restoration_value ?? 0,
    consent_required: props.consentRequired ?? props.consent_required,
    collects_personal_data: props.collectsPersonalData ?? props.collects_personal_data,
    motion_required: props.motionRequired ?? props.motion_required,
    reduced_motion_alternative: props.reducedMotionAlternative ?? props.reduced_motion_alternative,
    contrast_safe: props.contrastSafe ?? props.contrast_safe,
    cognitive_load: props.cognitiveLoad ?? props.cognitive_load
  };

  const firewall = createInterfaceFirewall({
    profile: props.policy || options.profile || "human_first",
    context: options.context || {}
  });

  return firewall.enforce(intent, {
    context: props.context || options.context || {},
    timestamp: options.timestamp
  });
}

export function createAccountableUI(React) {
  if (!React?.createElement) throw new Error("createAccountableUI requires a React-compatible object with createElement().");

  return function AccountableUI(props) {
    const result = evaluateAccountableProps(props, { context: props.context, timestamp: props.timestamp });
    if (!result.allowed) {
      if (typeof props.fallback === "function") return props.fallback(result);
      return props.fallback ?? null;
    }
    return React.createElement(React.Fragment, null, props.children);
  };
}
