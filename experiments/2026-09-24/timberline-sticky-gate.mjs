import { compileSourceBrowser } from "../../docs/aml-browser.js";

export const AML_SOURCE_BLOB = "e4e64a00d20718c1b74d8e5dd9f9dd08b1b84865";
export const POLICY = "restoration_value >= attention_cost";
export const ACTIONS = [
  { id: "SamplesAction", label: "Samples", path: "/samples" },
  { id: "BuildKitAction", label: "Build kit", path: "/ridge-kit" },
  { id: "CallAction", label: "Call to order", path: null },
];

// Fixed, project-declared design scores. These do not measure visitor attention.
export function evaluateStickyShopRoute(pathname, compiler = compileSourceBrowser) {
  const route = typeof pathname === "string" ? pathname.replace(/\/$/, "") || "/" : "/";
  const scores = {
    SamplesAction: route === "/samples" ? [3, 1] : [2, 4],
    BuildKitAction: route === "/ridge-kit" ? [3, 1] : [2, 4],
    CallAction: [1, 5],
  };
  const body = ACTIONS.map(({ id }) => {
    const [attention, restoration] = scores[id];
    return `engram ${id} {
      value: "A mobile shopping shortcut."
      purpose: "Provide a direct commerce path."
      attention_cost: ${attention.toFixed(1)}
      restoration_value: ${restoration.toFixed(1)}
    }`;
  }).join("\n");
  const source = `transmission "timberline_mobile_shortcuts" {\n${body}\n}`;
  try {
    const result = compiler(source);
    const decisions = Object.fromEntries(
      result.renderDecisions.map((decision) => [decision.identifier, decision])
    );
    if (ACTIONS.some(({ id }) => !decisions[id])) throw new Error("Missing mobile shortcut decision");
    return { route, source_blob: AML_SOURCE_BLOB, policy: POLICY, decisions, fallback: false };
  } catch {
    // Navigation must stay usable if a compiler update fails. No external logging or user data.
    return {
      route, source_blob: AML_SOURCE_BLOB, policy: POLICY, fallback: true,
      decisions: Object.fromEntries(ACTIONS.map(({ id }) => [id, {
        identifier: id, attention_cost: scores[id][0], restoration_value: scores[id][1],
        render_allowed: true, fallback_triggered: true,
      }])),
    };
  }
}