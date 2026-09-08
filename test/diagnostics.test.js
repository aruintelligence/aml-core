import test from "node:test";
import assert from "node:assert/strict";

import { analyzeAMT, compileSource } from "../index.js";

test("semantic diagnostics detect missing policy fields", () => {
  const source = `
transmission "diagnostic-demo" {
  engram IncompleteCard {
    value: "Visible but underspecified."
  }
}
`;

  const { amt } = compileSource(source, { timestamp: "1970-01-01T00:00:00.000Z" });
  const diagnostics = analyzeAMT(amt);
  const codes = new Set(diagnostics.map(item => item.code));

  assert.ok(codes.has("AML001"));
  assert.ok(codes.has("AML002"));
  assert.ok(codes.has("AML004"));
});

test("semantic diagnostics reject out-of-range v1 scores", () => {
  const source = `
transmission "diagnostic-range" {
  engram BadRange {
    purpose: "Exercise range validation."
    attention_cost: 11
    restoration_value: 12
  }
}
`;

  const { amt } = compileSource(source, { timestamp: "1970-01-01T00:00:00.000Z" });
  const diagnostics = analyzeAMT(amt);
  const codes = new Set(diagnostics.map(item => item.code));

  assert.ok(codes.has("AML003"));
  assert.ok(codes.has("AML005"));
});
