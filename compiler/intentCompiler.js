// compiler/intentCompiler.js
// Deterministic bridge from machine-generated intent JSON into ĀML source.

const VALID_NAME = /^[A-Za-z_Āā][A-Za-z0-9_Āā]*$/;

function assertName(value, label) {
  if (typeof value !== "string" || !VALID_NAME.test(value)) {
    throw new Error(`${label} must be a valid ĀML identifier.`);
  }
}

function renderValue(value) {
  if (typeof value === "number") return String(value);
  if (typeof value === "boolean") return value ? "true" : "false";
  if (typeof value === "string" && VALID_NAME.test(value) && !/\s/.test(value)) return value;
  return JSON.stringify(String(value));
}

function renderNode(node, depth = 1) {
  assertName(node.type, "node.type");
  const indent = "  ".repeat(depth);
  const id = node.identifier ? ` ${JSON.stringify(String(node.identifier))}` : "";
  const lines = [`${indent}${node.type}${id} {`];

  for (const [key, value] of Object.entries(node.properties || {})) {
    assertName(key, `property ${key}`);
    lines.push(`${indent}  ${key}: ${renderValue(value)}`);
  }

  for (const child of node.children || []) {
    lines.push(renderNode(child, depth + 1));
  }

  lines.push(`${indent}}`);
  return lines.join("\n");
}

export function generateAMLFromIntent(intent) {
  if (!intent || typeof intent !== "object" || Array.isArray(intent)) {
    throw new TypeError("ĀML intent must be an object.");
  }

  const transmission = intent.transmission || "generated_interface";
  const nodes = intent.nodes || [];
  if (!Array.isArray(nodes)) throw new Error("intent.nodes must be an array.");

  const lines = [`transmission ${JSON.stringify(String(transmission))} {`];
  for (const node of nodes) lines.push(renderNode(node, 1));
  lines.push("}");
  return `${lines.join("\n")}\n`;
}
