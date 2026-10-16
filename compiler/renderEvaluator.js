// compiler/renderEvaluator.js
// ĀML_CORE v1.2 research surface — policy-driven Render Evaluator

import { resolvePolicy } from "../runtime/policyEngine.js";
import { suppressRenderDecisionByAncestor } from "../runtime/attentionLedger.js";
import { validatePolicyContext } from "../runtime/contextValidation.js";

// Built-in policies also read these declarations directly from node.properties.
// A policy constraint must be evaluated even when no purpose or numeric score
// was supplied; otherwise the node would render without any decision.
const POLICY_DECLARATIONS = [
  "consent_required",
  "collects_personal_data",
  "motion_required",
  "reduced_motion_alternative",
  "contrast_safe",
  "cognitive_load"
];
const NUMERIC_POLICY_FIELDS = ["attention_cost", "restoration_value", "cognitive_load"];

export function evaluateRenderDecisions(amt, options = {}) {
  const decisions = [];
  const timestamp = options.timestamp ?? null;
  const policy = resolvePolicy(options.policy ?? "restorative_v1");
  const context = validatePolicyContext(options.context ?? {});

  for (const node of amt.root) {
    walkNode(node, decisions, timestamp, policy, context, null);
  }

  return decisions;
}

function walkNode(node, decisions, timestamp, policy, context, parentIndex) {
  for (const key of NUMERIC_POLICY_FIELDS) {
    const value = node.properties?.[key];
    if (Object.hasOwn(node.properties || {}, key) &&
        (typeof value !== "number" || !Number.isFinite(value) || value < 0)) {
      throw new TypeError(`property ${key} must be a non-negative finite number.`);
    }
  }
  let nextParentIndex = parentIndex;
  if (requiresRenderDecision(node)) {
    // Every node is evaluated by the policy, then its effective visibility is
    // bound to the nearest decision-bearing ancestor in the same preorder.
    let decision = createRenderDecision(node, timestamp, policy, context);
    if (parentIndex !== null && !decisions[parentIndex].render_allowed && decision.render_allowed) {
      decision = suppressRenderDecisionByAncestor(decision, parentIndex);
    }
    nextParentIndex = decisions.length;
    decisions.push(decision);
  }

  if (node.children && node.children.length > 0) {
    for (const child of node.children) {
      walkNode(child, decisions, timestamp, policy, context, nextParentIndex);
    }
  }
}

// The renderer uses the same predicate and traversal order to bind each
// decision to the node that produced it. Keep this in one place.
export function requiresRenderDecision(node) {
  // Every semantic block below a transmission can emit HTML. Do not let
  // missing optional metadata bypass a custom policy or its render decision.
  if (node.type === "MeaningProperty") return false;
  if (node.type !== "TransmissionNode") return true;

  // A transmission is structural by default, but explicit policy inputs on
  // the root can suppress the entire output.
  const metadata = node.render_metadata || {};
  const properties = node.properties || {};
  return Boolean(
    metadata.purpose ||
    metadata.memory_role ||
    metadata.user_effect ||
    typeof metadata.attention_cost === "number" ||
    typeof metadata.restoration_value === "number" ||
    POLICY_DECLARATIONS.some(key => Object.hasOwn(properties, key))
  );
}

// Index each decision's nearest decision-bearing ancestor in the same preorder
// used by evaluateRenderDecisions and the HTML generator. Structural nodes
// without a decision do not interrupt inheritance.
export function parentRenderDecisionIndices(amt) {
  const parents = [];
  let nextIndex = 0;

  function walk(node, parentIndex) {
    let childParentIndex = parentIndex;
    if (requiresRenderDecision(node)) {
      childParentIndex = nextIndex++;
      parents.push(parentIndex);
    }
    for (const child of node.children || []) walk(child, childParentIndex);
  }

  for (const node of amt.root) walk(node, null);
  return parents;
}

function createRenderDecision(node, timestamp, policy, context) {
  const metadata = node.render_metadata || {};

  // Preserve the distinction between an omitted score and an explicitly
  // declared zero. Policy engines may fall back to calculated metrics only
  // when the declaration is absent.
  const element = {
    purpose: metadata.purpose,
    memory_role: metadata.memory_role,
    user_effect: metadata.user_effect,
    attention_cost: typeof metadata.attention_cost === "number" ? metadata.attention_cost : undefined,
    restoration_value: typeof metadata.restoration_value === "number" ? metadata.restoration_value : undefined,
    animation_intensity: 1,
    cognitive_load: typeof metadata.attention_cost === "number" ? metadata.attention_cost : 1,
    interaction_interruptions: 1,
    reading_complexity: 1,
    visual_noise: 1,
    clarity: typeof metadata.restoration_value === "number" ? metadata.restoration_value : 1,
    usefulness: typeof metadata.restoration_value === "number" ? metadata.restoration_value : 1,
    emotional_regulation: typeof metadata.restoration_value === "number" ? metadata.restoration_value : 1,
    continuity: typeof metadata.restoration_value === "number" ? metadata.restoration_value : 1,
    aesthetic_coherence: typeof metadata.restoration_value === "number" ? metadata.restoration_value : 1
  };

  const result = policy.evaluate(element, { node, metadata, context });
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
