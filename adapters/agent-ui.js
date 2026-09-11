// adapters/agent-ui.js
// Renderer-agnostic governance boundary for AI/agent-generated UI components.
// This is an ĀML project adapter contract; it does not claim native compatibility
// with MCP Apps, A2UI, OpenUI, or any other external protocol.

import { createStreamingInterfaceFirewall } from "../runtime/streamingInterfaceFirewall.js";

export const AML_AGENT_UI_ENVELOPE = "aml-agent-ui-envelope/1";
export const AML_AGENT_UI_RESULT = "aml-agent-ui-governance-result/1";

function assertObject(value, name) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new TypeError(`${name} must be an object.`);
  }
}

function normalizeComponent(component, index) {
  assertObject(component, `components[${index}]`);
  const id = component.id || component.identifier || `component_${index + 1}`;
  const type = component.type || "component";
  const governance = component.governance || component.aml;
  assertObject(governance, `components[${index}].governance`);

  if (typeof governance.purpose !== "string" || governance.purpose.length === 0) {
    throw new Error(`components[${index}].governance.purpose is required.`);
  }
  for (const key of ["attention_cost", "restoration_value"]) {
    if (!Number.isFinite(governance[key])) {
      throw new Error(`components[${index}].governance.${key} must be a finite number.`);
    }
  }

  const props = structuredClone(component.props || {});
  const content =
    governance.content ??
    props.text ??
    props.label ??
    props.title ??
    `[${type}]`;

  return {
    original: structuredClone(component),
    node: {
      type: governance.aml_type || "message",
      identifier: String(id),
      properties: {
        ...structuredClone(governance),
        purpose: governance.purpose,
        content,
        attention_cost: governance.attention_cost,
        restoration_value: governance.restoration_value
      }
    }
  };
}

export function evaluateAgentUI(envelope, options = {}) {
  assertObject(envelope, "envelope");
  if (envelope.protocol && envelope.protocol !== AML_AGENT_UI_ENVELOPE) {
    throw new Error(`Unsupported agent UI protocol: ${envelope.protocol}`);
  }
  if (!Array.isArray(envelope.components)) {
    throw new Error("envelope.components must be an array.");
  }

  const surfaceId = envelope.surface_id || "agent_ui_surface";
  const normalized = envelope.components.map(normalizeComponent);
  const firewall = createStreamingInterfaceFirewall({
    transmission: surfaceId,
    profile: options.profile || "calm_default",
    mode: options.mode || "enforce",
    failure_mode: options.failure_mode || "closed",
    context: options.context || {}
  });

  const decisions = normalized.map(({ original, node }) => {
    const evaluated = firewall.push(node, {
      timestamp: options.timestamp,
      context: options.context || {}
    });
    return {
      id: node.identifier,
      component_type: original.type || "component",
      aml_allowed: evaluated.aml_allowed,
      effective_allowed: evaluated.effective_allowed,
      would_suppress: evaluated.would_suppress,
      evaluation_error: evaluated.evaluation_error,
      receipt_sha256: evaluated.receipt_sha256,
      output_sha256: evaluated.output_sha256
    };
  });

  const result = firewall.finalize();
  const renderable = normalized
    .filter((_, index) => decisions[index].effective_allowed === true)
    .map(({ original }) => original);
  const suppressed = normalized
    .filter((_, index) => decisions[index].effective_allowed !== true)
    .map(({ original }) => original);

  return {
    protocol: AML_AGENT_UI_RESULT,
    surface_id: surfaceId,
    mode: options.mode || "enforce",
    policy_profile: options.profile || "calm_default",
    total: decisions.length,
    allowed: decisions.filter((d) => d.aml_allowed === true).length,
    suppressed: decisions.filter((d) => d.aml_allowed === false).length,
    errors: decisions.filter((d) => d.evaluation_error).length,
    decisions,
    renderable_components: renderable,
    suppressed_components: suppressed,
    streaming_result: result
  };
}
