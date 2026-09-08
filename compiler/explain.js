// compiler/explain.js
// Produce a compact explanation layer from compiled ĀML artifacts.

import { analyzeAMT } from "./diagnostics.js";

export function explainCompilation(compiled) {
  if (!compiled?.amt || !Array.isArray(compiled?.renderDecisions)) {
    throw new TypeError("Expected a compiled ĀML result containing amt and renderDecisions.");
  }

  const diagnostics = analyzeAMT(compiled.amt);
  const diagnosticsByIdentifier = new Map();

  for (const diagnostic of diagnostics) {
    const key = diagnostic.identifier || diagnostic.name || diagnostic.node_type;
    if (!diagnosticsByIdentifier.has(key)) diagnosticsByIdentifier.set(key, []);
    diagnosticsByIdentifier.get(key).push({
      level: diagnostic.level,
      code: diagnostic.code,
      message: diagnostic.message
    });
  }

  const elements = compiled.renderDecisions.map(decision => {
    const key = decision.identifier || decision.name || decision.node_type;
    const delta = Number((decision.restoration_value - decision.attention_cost).toFixed(4));

    return {
      identifier: decision.identifier ?? null,
      node_type: decision.node_type,
      purpose: decision.purpose,
      memory_role: decision.memory_role,
      user_effect: decision.user_effect,
      attention_cost: decision.attention_cost,
      restoration_value: decision.restoration_value,
      value_delta: delta,
      decision: decision.render_allowed ? "allow" : "suppress",
      explanation: decision.render_allowed
        ? `Declared restoration value exceeds or equals attention cost by ${delta}.`
        : `Declared attention cost exceeds restoration value by ${Math.abs(delta)}.`,
      diagnostics: diagnosticsByIdentifier.get(key) || []
    };
  });

  const allowed = elements.filter(element => element.decision === "allow").length;
  const suppressed = elements.length - allowed;

  return {
    protocol: "ĀML Explanation",
    version: "1.1.0",
    summary: {
      meaning_bearing_elements: elements.length,
      allowed,
      suppressed,
      diagnostics: diagnostics.length
    },
    elements,
    diagnostics
  };
}
