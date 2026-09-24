import assert from "node:assert/strict";
import { ACTIONS, AML_SOURCE_BLOB, evaluateStickyShopRoute } from "./timberline-sticky-gate.mjs";

// Run from repo root: node experiments/2026-09-24/verify-timberline.mjs
const cases = [
  { path: "/", expected: [true, true, true] },
  { path: "/samples", expected: [false, true, true] },
  { path: "/ridge-kit", expected: [true, false, true] },
  { path: "/putting-greens", expected: [true, true, true] },
];
for (const item of cases) {
  const gate = evaluateStickyShopRoute(item.path);
  assert.equal(gate.fallback, false, item.path);
  assert.equal(gate.source_blob, AML_SOURCE_BLOB);
  const actual = ACTIONS.map(({ id }) => gate.decisions[id].render_allowed);
  assert.deepEqual(actual, item.expected, item.path);
  assert.equal(gate.decisions.CallAction.render_allowed, true);
  console.log(`${item.path}: ${actual.map((value) => value ? "ALLOW" : "SUPPRESS").join(", ")}`);
}
for (const compiler of [
  () => { throw new Error("compiler unavailable"); },
  () => ({ renderDecisions: [] }),
]) {
  const gate = evaluateStickyShopRoute("/samples", compiler);
  assert.equal(gate.fallback, true);
  assert.equal(ACTIONS.every(({ id }) => gate.decisions[id].render_allowed), true);
}
console.log("PASS: four routes and two fail-open conditions; no visitor outcome measured.");
