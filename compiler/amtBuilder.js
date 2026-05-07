// compiler/amtBuilder.js
// ĀML_CORE v1.0 — Abstract Meaning Tree Builder
// Converts parsed AML blocks into semantic AMT nodes.

export function buildAMT(ast) {
  return {
    type: "AbstractMeaningTree",
    version: "1.0",
    root: ast.body.map(transformNode)
  };
}

function transformNode(node) {
  if (node.type === "Property") {
    return {
      type: "MeaningProperty",
      name: node.name,
      value: node.value
    };
  }

  if (node.type === "Block") {
    const base = {
      type: mapBlockType(node.name),
      name: node.name,
      identifier: node.identifier,
      children: node.children.map(transformNode),
      properties: collectProperties(node.children)
    };

    base.meaning = inferMeaning(base);
    base.render_metadata = extractRenderMetadata(base.properties);

    return base;
  }

  return {
    type: "UnknownNode",
    raw: node
  };
}

function mapBlockType(name) {
  const types = {
    transmission: "TransmissionNode",
    engram: "EngramNode",
    coherence_gate: "CoherenceGateNode",
    mirror: "MirrorNode",
    condition: "ConditionNode",
    behavior: "BehaviorNode",
    render: "RenderNode",
    runtime: "RuntimeNode",
    attention: "AttentionNode",
    memory: "MemoryNode",
    garden: "GardenNode"
  };

  return types[name] || "SemanticBlockNode";
}

function collectProperties(children) {
  const properties = {};

  for (const child of children) {
    if (child.type === "Property") {
      properties[child.name] = child.value;
    }
  }

  return properties;
}

function extractRenderMetadata(properties) {
  return {
    purpose: properties.purpose || null,
    memory_role: properties.memory_role || null,
    user_effect: properties.user_effect || null,
    attention_cost:
      typeof properties.attention_cost === "number"
        ? properties.attention_cost
        : null,
    restoration_value:
      typeof properties.restoration_value === "number"
        ? properties.restoration_value
        : null
  };
}

function inferMeaning(node) {
  if (node.type === "TransmissionNode") {
    return "semantic execution root";
  }

  if (node.type === "EngramNode") {
    return "persistent meaning structure";
  }

  if (node.type === "CoherenceGateNode") {
    return "runtime coherence regulator";
  }

  if (node.type === "MirrorNode") {
    return "reflective interaction structure";
  }

  if (node.type === "ConditionNode") {
    return "runtime evaluation condition";
  }

  if (node.type === "BehaviorNode") {
    return "adaptive rendering behavior";
  }

  return "semantic structure";
}
