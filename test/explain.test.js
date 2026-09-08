import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";

import { compileSource, explainCompilation } from "../index.js";

test("AML explanation summarizes allow and suppress decisions", () => {
  const source = fs.readFileSync("conformance/allow.aml", "utf8");
  const compiled = compileSource(source, { timestamp: "1970-01-01T00:00:00.000Z" });
  const explanation = explainCompilation(compiled);

  assert.equal(explanation.protocol, "ĀML Explanation");
  assert.equal(explanation.summary.meaning_bearing_elements, compiled.renderDecisions.length);
  assert.equal(explanation.summary.allowed, compiled.renderDecisions.length);
  assert.equal(explanation.summary.suppressed, 0);
  assert.ok(explanation.elements.every(element => typeof element.explanation === "string"));
});

test("AML explanation reports negative value delta for suppressed content", () => {
  const source = fs.readFileSync("conformance/suppress.aml", "utf8");
  const compiled = compileSource(source, { timestamp: "1970-01-01T00:00:00.000Z" });
  const explanation = explainCompilation(compiled);
  const suppressed = explanation.elements.find(element => element.decision === "suppress");

  assert.ok(suppressed);
  assert.ok(suppressed.value_delta < 0);
});
