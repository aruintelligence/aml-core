// compiler/renderEvaluator.js
// ĀML_CORE v1.2 research surface — policy-driven Render Evaluator

import { resolvePolicy } from "../runtime/policyEngine.js";

export function evaluateRenderDecisions(amt, options = {}) {
  const decisions = [];
  const timestamp = options.timestamp ?? null;
  const policy = resolvePolicy(options.policy ?? "restorative_v1");

  for (const node of amt.root) {
    walkNode(node, decisions, timestamp, policy);
  }

  return decisions;
}

function walkNode(node, decisions, timestamp, policy) {
  const metadata = node.render_metadata || {};

  const hasRenderableMetadata =
    metadata.purpose ||
    metadata.memory_role ||
    metadata.user_effect ||
    typeof metadata.attention_cost === "number" ||
    typeof metadata.restoration_value === "number";

  if (hasRenderableMetadata) {
    decisions.push(createRenderDecision(node, timestamp, policy));
  }

  if (node.children && node.children.length > 0) {
    for (const child of node.children) {
      walkNode(child, decisions, timestamp, policy);
    }
  }
}

function createRenderDecision(node, timestamp, policy) {
  const metadata = node.render_metadata || {};

  const element = {
    purpose: metadata.purpose,
    memory_role: metadata.memory_role,
    user_effect: metadata.user_effect,
    attention_cost: typeof metadata.attention_cost === "number" ? metadata.attention_cost : 0,
    restoration_value: typeof metadata.restoration_value === "number" ? metadata.restoration_value : 0,
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

  const result = policy.evaluate(element, { node, metadata });
  if (!result || typeof result.render_allowed !== "boolean") {
    throw new Error(`ĀML policy ${policy.id} must return render_allowed as a boolean.`);
  }

  return {
    node_type: node.type,
    name: node.name,
    identifier: node.identifier,
    purpose: metadata.purpose || null,
    memory_role: metadata.memory_role || null,
    user_effect: metadata.user_effect || null,
    policy_id: result.policy_id || policy.id,
    policy_rationale: result.rationale || null,
    attention_cost: result.attention_cost,
    restoration_value: result.restoration_value,
    calculated_attention_cost: result.calculated_attention_cost ?? null,
    calculated_restoration_value: result.calculated_restoration_value ?? null,
    render_allowed: result.render_allowed,
    fallback_triggered: result.fallback_triggered ?? !result.render_allowed,
    timestamp: timestamp ?? new Date().toISOString()
  };
}
