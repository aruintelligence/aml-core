import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";

import { compileSource } from "../index.js";

function decisionFor(file) {
  const source = fs.readFileSync(file, "utf8");
  const result = compileSource(source);
  assert.ok(result.renderDecisions.length > 0, `${file} should emit a render decision`);
  return result.renderDecisions[0];
}

test("canonical allow fixture is render-allowed", () => {
  const decision = decisionFor("conformance/allow.aml");
  assert.equal(decision.render_allowed, true);
  assert.equal(decision.fallback_triggered, false);
  assert.ok(decision.restoration_value >= decision.attention_cost);
});

test("canonical suppress fixture triggers fallback", () => {
  const decision = decisionFor("conformance/suppress.aml");
  assert.equal(decision.render_allowed, false);
  assert.equal(decision.fallback_triggered, true);
  assert.ok(decision.restoration_value < decision.attention_cost);
});
