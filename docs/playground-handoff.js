import { shareableStudioUrl } from "./quickstart-core.js";

// A deliberately narrow handoff: one compiled engram becomes one browser gate.
// The compiler does not turn an arbitrary ĀML program into HTML.
export function studioHandoffUrl(compiled, playgroundUrl) {
  if (compiled?.renderDecisions?.length !== 1) return null;
  const decision = compiled.renderDecisions[0];
  if (decision.node_type !== "EngramNode") return null;

  const nodes = [];
  function visit(node) {
    nodes.push(node);
    for (const child of node.children || []) visit(child);
  }
  for (const root of compiled.amt?.root || []) visit(root);
  const matches = nodes.filter(node =>
    node.type === "EngramNode" && node.identifier === decision.identifier &&
    node.properties?.purpose === decision.purpose &&
    node.properties?.attention_cost === decision.attention_cost &&
    node.properties?.restoration_value === decision.restoration_value);
  if (matches.length !== 1) return null;

  const { value, purpose, attention_cost: attention, restoration_value: restoration } = matches[0].properties;
  if (typeof value !== "string" || !value.trim() || value !== value.trim() || value.length > 120 ||
      typeof purpose !== "string" || !purpose.trim() || purpose !== purpose.trim() || purpose.length > 120 ||
      ![attention, restoration].every(number => Number.isInteger(number) && number >= 0 && number <= 10)) return null;
  const studioUrl = new URL("./quickstart.html", playgroundUrl);
  return shareableStudioUrl({ purpose, label: value, attention, restoration, mode: "enforce" }, studioUrl.href);
}
