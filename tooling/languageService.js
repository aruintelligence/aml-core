// tooling/languageService.js
// Dependency-free language intelligence shared by editors, agents, and future LSP adapters.

const BLOCKS = {
  transmission: "Top-level semantic execution container.",
  engram: "Meaning-bearing interface or persistent semantic structure.",
  coherence_gate: "Semantic/runtime coherence regulation block.",
  ethical_render_gate: "Policy declaration block for accountable rendering.",
  mirror: "Reflective interaction structure.",
  condition: "Runtime evaluation condition.",
  behavior: "Adaptive rendering behavior.",
  render: "Rendering-oriented semantic block.",
  runtime: "Runtime configuration block.",
  attention: "Attention-model configuration block.",
  memory: "Memory-oriented semantic block.",
  garden: "General semantic grouping block."
};

const PROPERTIES = {
  value: "Human-readable semantic value carried by a node.",
  purpose: "Declared reason the meaning-bearing node exists.",
  memory_role: "Declared role in the interface or memory model.",
  user_effect: "Declared intended effect on the user experience.",
  attention_cost: "Prototype v1 modeled attention cost, normally 0–10.",
  restoration_value: "Prototype v1 declared restoration value, normally 0–10.",
  rule: "Policy expression, currently supporting one binary comparison.",
  rendering_mode: "Declared rendering behavior or policy mode.",
  degraded_threshold: "Prototype threshold metadata for degraded rendering.",
  suppression_threshold: "Prototype threshold metadata for suppression."
};

const OPERATORS = [">", ">=", "<", "<=", "=", "==", "!="];

export function getCompletionItems(prefix = "") {
  const normalized = String(prefix).toLowerCase();
  const items = [
    ...Object.entries(BLOCKS).map(([label, documentation]) => ({
      label,
      kind: "block",
      documentation,
      insertText: `${label} $1 {\n  $0\n}`
    })),
    ...Object.entries(PROPERTIES).map(([label, documentation]) => ({
      label,
      kind: "property",
      documentation,
      insertText: `${label}: $0`
    })),
    ...OPERATORS.map(label => ({
      label,
      kind: "operator",
      documentation: "ĀML v1.1 comparison operator.",
      insertText: label
    }))
  ];

  return normalized
    ? items.filter(item => item.label.toLowerCase().startsWith(normalized))
    : items;
}

export function getHoverInfo(symbol) {
  if (BLOCKS[symbol]) {
    return { symbol, kind: "block", documentation: BLOCKS[symbol] };
  }
  if (PROPERTIES[symbol]) {
    return { symbol, kind: "property", documentation: PROPERTIES[symbol] };
  }
  if (OPERATORS.includes(symbol)) {
    return { symbol, kind: "operator", documentation: "ĀML v1.1 comparison operator." };
  }
  return null;
}

export function getLanguageCatalog() {
  return {
    protocol: "ĀML Language Intelligence",
    version: "1.1.0",
    blocks: BLOCKS,
    properties: PROPERTIES,
    operators: OPERATORS
  };
}
