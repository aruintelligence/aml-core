// compiler/htmlGenerator.js
// ĀML_CORE v1.0 — Initial HTML Generator
// Converts AMT semantic nodes into HTML with accountability metadata.

export function generateHTML(amt, renderDecisions = []) {
  const body = amt.root.map((node) => renderNode(node, renderDecisions)).join("\n");

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

function renderNode(node, renderDecisions) {
  const decision = findDecision(node, renderDecisions);

  const attrs = buildAttributes(node, decision);

  if (decision && decision.render_allowed === false) {
    return `<section ${attrs} hidden data-aml-suppressed="true">
  <p>Rendering suppressed by EthicalRenderGate.</p>
</section>`;
  }

  if (node.type === "TransmissionNode") {
    return `<main ${attrs}>
${renderChildren(node, renderDecisions)}
</main>`;
  }

  if (node.type === "EngramNode") {
    const value = node.properties?.value || node.identifier || "Engram";

    return `<section ${attrs}>
  <h2>${escapeHTML(value)}</h2>
${renderChildren(node, renderDecisions)}
</section>`;
  }

  if (node.type === "MirrorNode") {
    const speak = node.properties?.speak || "";
    const reflect = node.properties?.reflect || "";

    return `<section ${attrs}>
  <p>${escapeHTML(speak)}</p>
  <p><em>${escapeHTML(reflect)}</em></p>
${renderChildren(node, renderDecisions)}
</section>`;
  }

  if (node.type === "CoherenceGateNode") {
    return `<section ${attrs}>
${renderChildren(node, renderDecisions)}
</section>`;
  }

  if (node.type === "MeaningProperty") {
    return "";
  }

  return `<section ${attrs}>
${renderChildren(node, renderDecisions)}
</section>`;
}

function renderChildren(node, renderDecisions) {
  if (!node.children || node.children.length === 0) return "";

  return node.children
    .map((child) => renderNode(child, renderDecisions))
    .filter(Boolean)
    .join("\n");
}

function findDecision(node, renderDecisions) {
  return renderDecisions.find((decision) => {
    return (
      decision.identifier === node.identifier ||
      decision.node_type === node.type ||
      decision.purpose === node.render_metadata?.purpose
    );
  });
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
  return value
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;");
}
