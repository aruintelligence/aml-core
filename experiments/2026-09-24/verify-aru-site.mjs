import assert from "node:assert/strict";
import { compileSourceBrowser } from "../../docs/aml-browser.js";

// Run from repository root: node experiments/2026-09-24/verify-aru-site.mjs
const cases = [
  ["deep-article", 3.2, 9.1, true],
  ["focus-reminder", 2.8, 7.4, true],
  ["infinite-scroll", 8.5, 3.0, false],
  ["rage-bait", 7.5, 2.0, false],
  ["equal-boundary", 4.0, 4.0, true],
];
for (const [name, attention, restoration, expected] of cases) {
  const source = `transmission "aru_site_lab" {
    engram GateLab {
      value: "Inspect an illustrative policy decision."
      purpose: "Explain a declared attention/restoration scenario."
      attention_cost: ${attention.toFixed(1)}
      restoration_value: ${restoration.toFixed(1)}
    }
  }`;
  const output = compileSourceBrowser(source);
  const decision = output.renderDecisions.find((item) => item.identifier === "GateLab");
  assert.ok(decision, `${name}: decision exists`);
  assert.equal(decision.attention_cost, attention, `${name}: attention input preserved`);
  assert.equal(decision.restoration_value, restoration, `${name}: restoration input preserved`);
  assert.equal(decision.render_allowed, expected, `${name}: expected policy outcome`);
  assert.equal(decision.fallback_triggered, !expected, `${name}: fallback outcome`);
  console.log(`${name}: ${expected ? "ALLOW" : "SUPPRESS"} (${attention.toFixed(1)}/${restoration.toFixed(1)})`);
}
console.log("PASS: 5/5 declared scenarios; no human outcome measured.");
