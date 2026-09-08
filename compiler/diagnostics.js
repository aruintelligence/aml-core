// compiler/diagnostics.js
// Semantic diagnostics for meaning-bearing AML nodes.

export function analyzeAMT(amt) {
  const diagnostics = [];

  function add(level, code, message, node) {
    diagnostics.push({
      level,
      code,
      message,
      node_type: node.type,
      name: node.name,
      identifier: node.identifier ?? null
    });
  }

  function walk(node) {
    const metadata = node.render_metadata || {};
    const isMeaningBearing =
      node.type === "EngramNode" ||
      metadata.purpose ||
      metadata.memory_role ||
      metadata.user_effect ||
      typeof metadata.attention_cost === "number" ||
      typeof metadata.restoration_value === "number";

    if (isMeaningBearing) {
      if (!metadata.purpose || !String(metadata.purpose).trim()) {
        add("warning", "AML001", "Meaning-bearing node has no declared purpose.", node);
      }

      if (typeof metadata.attention_cost !== "number") {
        add("warning", "AML002", "Meaning-bearing node has no numeric attention_cost.", node);
      } else if (metadata.attention_cost < 0 || metadata.attention_cost > 10) {
        add("error", "AML003", "attention_cost must be between 0 and 10 in the v1 model.", node);
      }

      if (typeof metadata.restoration_value !== "number") {
        add("warning", "AML004", "Meaning-bearing node has no numeric restoration_value.", node);
      } else if (metadata.restoration_value < 0 || metadata.restoration_value > 10) {
        add("error", "AML005", "restoration_value must be between 0 and 10 in the v1 model.", node);
      }
    }

    for (const child of node.children || []) walk(child);
  }

  for (const node of amt.root || []) walk(node);

  return diagnostics;
}
