import { shareableStudioUrl } from "./quickstart-core.js";

// Each eligible engram can be explored as one browser gate. This does not
// turn a whole ĀML program into an HTML interface.
export function studioHandoffUrls(compiled, playgroundUrl) {
  if (!Array.isArray(compiled?.renderDecisions)) return [];
  const nodes = [];
  function visit(node) {
    nodes.push(node);
    for (const child of node.children || []) visit(child);
  }
  for (const root of compiled.amt?.root || []) visit(root);
  const decisions = compiled.renderDecisions;
  const sameDeclaration = (node, decision) =>
    node.type === "EngramNode" && node.identifier === decision.identifier &&
    node.properties?.purpose === decision.purpose &&
    node.properties?.attention_cost === decision.attention_cost &&
    node.properties?.restoration_value === decision.restoration_value;
  const studioUrl = new URL("./quickstart.html", playgroundUrl);
  return decisions.map(decision => {
    if (decision.node_type !== "EngramNode") return null;
    // Do not guess which source node a repeated or fabricated decision means.
    const matches = nodes.filter(node => sameDeclaration(node, decision));
    const duplicateDecisions = decisions.filter(item =>
      item.node_type === "EngramNode" &&
      item.identifier === decision.identifier &&
      item.purpose === decision.purpose &&
      item.attention_cost === decision.attention_cost &&
      item.restoration_value === decision.restoration_value);
    if (matches.length !== 1 || duplicateDecisions.length !== 1) return null;

    const { value, purpose, attention_cost: attention, restoration_value: restoration } = matches[0].properties;
    if (typeof value !== "string" || !value.trim() || value !== value.trim() || value.length > 120 ||
        typeof purpose !== "string" || !purpose.trim() || purpose !== purpose.trim() || purpose.length > 120 ||
        ![attention, restoration].every(number => Number.isInteger(number) && number >= 0 && number <= 10)) return null;
    return shareableStudioUrl({ purpose, label: value, attention, restoration, mode: "enforce" }, studioUrl.href);
  });
}

export function studioHandoffUrl(compiled, playgroundUrl) {
  if (compiled?.renderDecisions?.length !== 1) return null;
  return studioHandoffUrls(compiled, playgroundUrl)[0];
}
