// compiler/intentCompiler.js
// Deterministic bridge from machine-generated intent JSON into ĀML source.

const VALID_NAME = /^[A-Za-z_Āā][A-Za-z0-9_Āā]*$/;
const NUMERIC_POLICY_FIELDS = new Set(["attention_cost", "restoration_value", "cognitive_load"]);

function assertName(value, label) {
  if (typeof value !== "string" || !VALID_NAME.test(value)) {
    throw new Error(`${label} must be a valid ĀML identifier.`);
  }
}

function renderValue(value, label) {
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new TypeError(`${label} must be finite.`);
    return String(value);
  }
  if (typeof value === "boolean") return value ? "true" : "false";
  if (typeof value === "string" && VALID_NAME.test(value) && !/\s/.test(value)) return value;
  if (typeof value === "string") return JSON.stringify(value);
  throw new TypeError(`${label} must be a string, finite number, or boolean.`);
}

function renderNode(node, depth = 1) {
  if (!node || typeof node !== "object" || Array.isArray(node)) {
    throw new TypeError("intent.nodes entries must be objects.");
  }
  assertName(node.type, "node.type");
  const indent = "  ".repeat(depth);
  if (node.identifier != null && typeof node.identifier !== "string") {
    throw new TypeError("node.identifier must be a string when supplied.");
  }
  const id = node.identifier == null ? "" : ` ${JSON.stringify(node.identifier)}`;
  const lines = [`${indent}${node.type}${id} {`];

  const properties = node.properties === undefined ? {} : node.properties;
  if (!properties || typeof properties !== "object" || Array.isArray(properties)) {
    throw new TypeError("node.properties must be an object.");
  }
  for (const [key, value] of Object.entries(properties)) {
    assertName(key, `property ${key}`);
    if (NUMERIC_POLICY_FIELDS.has(key) &&
        (typeof value !== "number" || !Number.isFinite(value) || value < 0)) {
      throw new TypeError(`property ${key} must be a non-negative finite number.`);
    }
    lines.push(`${indent}  ${key}: ${renderValue(value, `property ${key}`)}`);
  }

  const children = node.children === undefined ? [] : node.children;
  if (!Array.isArray(children)) throw new TypeError("node.children must be an array.");
  for (const child of children) {
    lines.push(renderNode(child, depth + 1));
  }

  lines.push(`${indent}}`);
  return lines.join("\n");
}

export function generateAMLFromIntent(intent) {
  if (!intent || typeof intent !== "object" || Array.isArray(intent)) {
    throw new TypeError("ĀML intent must be an object.");
  }

  const transmission = intent.transmission === undefined ? "generated_interface" : intent.transmission;
  if (typeof transmission !== "string") throw new TypeError("intent.transmission must be a string.");
  const nodes = intent.nodes === undefined ? [] : intent.nodes;
  if (!Array.isArray(nodes)) throw new Error("intent.nodes must be an array.");

  const lines = [`transmission ${JSON.stringify(transmission)} {`];
  for (const node of nodes) lines.push(renderNode(node, 1));
  lines.push("}");
  return `${lines.join("\n")}\n`;
}
