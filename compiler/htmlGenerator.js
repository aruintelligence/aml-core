// compiler/htmlGenerator.js
// ĀML_CORE v1.0 — Initial HTML Generator
// Converts AMT semantic nodes into HTML with accountability metadata.

import { requiresRenderDecision } from "./renderEvaluator.js";

export function generateHTML(amt, renderDecisions = []) {
  const decisionsByNode = bindRenderDecisions(amt, renderDecisions);
  const body = amt.root.map((node) => renderNode(node, decisionsByNode)).join("\n");

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>ĀML Output</title>
</head>
<body>
${body}
</body>
</html>`;
}

function renderNode(node, decisionsByNode) {
  const decision = decisionsByNode.get(node);

  if (decision && decision.render_allowed === false) {
    // Hidden HTML remains inspectable. Keep all node-derived metadata in the
    // receipt, not in a suppressed element's DOM attributes.
    return `<section hidden data-aml-suppressed="true" data-render-allowed="false">
  <p>Rendering suppressed by EthicalRenderGate.</p>
</section>`;
  }

  const attrs = buildAttributes(node, decision);

  if (node.type === "TransmissionNode") {
    return `<main ${attrs}>
${renderChildren(node, decisionsByNode)}
</main>`;
  }

  if (node.type === "EngramNode") {
    const value = node.properties?.value ?? node.identifier ?? "Engram";

    return `<section ${attrs}>
  <h2>${escapeHTML(value)}</h2>
${renderChildren(node, decisionsByNode)}
</section>`;
  }

  if (node.type === "MirrorNode") {
    const speak = node.properties?.speak ?? "";
    const reflect = node.properties?.reflect ?? "";

    return `<section ${attrs}>
  <p>${escapeHTML(speak)}</p>
  <p><em>${escapeHTML(reflect)}</em></p>
${renderChildren(node, decisionsByNode)}
</section>`;
  }

  if (node.type === "CoherenceGateNode") {
    return `<section ${attrs}>
${renderChildren(node, decisionsByNode)}
</section>`;
  }

  if (node.type === "MeaningProperty") {
    return "";
  }

  const content = node.properties?.content;
  const visibleContent = content === undefined ? "" : `  <p>${escapeHTML(content)}</p>\n`;
  return `<section ${attrs}>
${visibleContent}${renderChildren(node, decisionsByNode)}
</section>`;
}

function renderChildren(node, decisionsByNode) {
  if (!node.children || node.children.length === 0) return "";

  return node.children
    .map((child) => renderNode(child, decisionsByNode))
    .filter(Boolean)
    .join("\n");
}

function bindRenderDecisions(amt, renderDecisions) {
  if (!Array.isArray(renderDecisions)) {
    throw new TypeError("Render decisions must be an array.");
  }

  const decisionsByNode = new WeakMap();
  let cursor = 0;

  function walk(node) {
    if (requiresRenderDecision(node)) {
      // evaluateRenderDecisions emits one decision per eligible node in
      // preorder. Names, types and purposes are not unique node identities.
      const decision = renderDecisions[cursor++];
      const metadata = node.render_metadata || {};
      const identity = {
        node_type: node.type,
        name: node.name,
        identifier: node.identifier,
        purpose: metadata.purpose || null,
        memory_role: metadata.memory_role || null,
        user_effect: metadata.user_effect || null
      };
      if (!decision || typeof decision.render_allowed !== "boolean" ||
          Object.entries(identity).some(([key, value]) => decision[key] !== value)) {
        throw new Error(`Render decision does not match semantic node at index ${cursor - 1}.`);
      }
      decisionsByNode.set(node, decision);
    }

    for (const child of node.children || []) walk(child);
  }

  for (const node of amt.root) walk(node);
  if (cursor !== renderDecisions.length) {
    throw new Error("Render decisions contain entries without semantic nodes.");
  }
  return decisionsByNode;
}

function buildAttributes(node, decision) {
  const attributes = {
    "data-aml-node": node.type,
    "data-aml-name": node.name,
    "data-aml-identifier": node.identifier,
    "data-purpose": node.render_metadata?.purpose,
    "data-memory-role": node.render_metadata?.memory_role,
    "data-user-effect": node.render_metadata?.user_effect,
    "data-attention-cost": decision?.attention_cost ?? node.render_metadata?.attention_cost,
    "data-restoration-value": decision?.restoration_value ?? node.render_metadata?.restoration_value,
    "data-render-allowed": decision?.render_allowed
  };

  return Object.entries(attributes)
    .filter(([, value]) => value !== null && value !== undefined && value !== "")
    .map(([key, value]) => `${key}="${escapeHTML(String(value))}"`)
    .join(" ");
}

function escapeHTML(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;");
}
