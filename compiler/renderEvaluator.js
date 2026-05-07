// compiler/renderEvaluator.js
// ĀML_CORE v1.0 — Render Evaluator
// Walks the AMT, applies EthicalRenderGate logic, and produces render decisions.

import { ethicalRenderGate } from "../runtime/ethicalRenderGate.js";

export function evaluateRenderDecisions(amt) {
  const decisions = [];

  for (const node of amt.root) {
    walkNode(node, decisions);
  }

  return decisions;
}

function walkNode(node, decisions) {
  const metadata = node.render_metadata || {};

  const hasRenderableMetadata =
    metadata.purpose ||
    metadata.memory_role ||
    metadata.user_effect ||
    typeof metadata.attention_cost === "number" ||
    typeof metadata.restoration_value === "number";

  if (hasRenderableMetadata) {
    decisions.push(createRenderDecision(node));
  }

  if (node.children && node.children.length > 0) {
    for (const child of node.children) {
      walkNode(child, decisions);
    }
  }
}

function createRenderDecision(node) {
  const metadata = node.render_metadata || {};

  const element = {
    purpose: metadata.purpose,
    memory_role: metadata.memory_role,
    user_effect: metadata.user_effect,

    attention_cost:
      typeof metadata.attention_cost === "number"
        ? metadata.attention_cost
        : 0,

    restoration_value:
      typeof metadata.restoration_value === "number"
        ? metadata.restoration_value
        : 0,

    animation_intensity: 1,
    cognitive_load: metadata.attention_cost || 1,
    interaction_interruptions: 1,
    reading_complexity: 1,
    visual_noise: 1,

    clarity: metadata.restoration_value || 1,
    usefulness: metadata.restoration_value || 1,
    emotional_regulation: metadata.restoration_value || 1,
    continuity: metadata.restoration_value || 1,
    aesthetic_coherence: metadata.restoration_value || 1
  };

  const gateResult = ethicalRenderGate(element);

  return {
    node_type: node.type,
    name: node.name,
    identifier: node.identifier,
    purpose: metadata.purpose || null,
    memory_role: metadata.memory_role || null,
    user_effect: metadata.user_effect || null,
    attention_cost:
      typeof metadata.attention_cost === "number"
        ? metadata.attention_cost
        : gateResult.attention_cost,
    restoration_value:
      typeof metadata.restoration_value === "number"
        ? metadata.restoration_value
        : gateResult.restoration_value,
    calculated_attention_cost: gateResult.attention_cost,
    calculated_restoration_value: gateResult.restoration_value,
    render_allowed:
      (metadata.restoration_value ?? gateResult.restoration_value) >=
      (metadata.attention_cost ?? gateResult.attention_cost),
    fallback_triggered:
      !(
        (metadata.restoration_value ?? gateResult.restoration_value) >=
        (metadata.attention_cost ?? gateResult.attention_cost)
      ),
    timestamp: new Date().toISOString()
  };
}
