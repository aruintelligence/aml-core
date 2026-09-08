import test from "node:test";
import assert from "node:assert/strict";

import { compileAML, compileSource, ethicalRenderGate } from "../index.js";

test("package entry point exposes the public AML API", () => {
  assert.equal(typeof compileAML, "function");
  assert.equal(typeof compileSource, "function");
  assert.equal(typeof ethicalRenderGate, "function");
});

test("compileSource compiles AML entirely in memory", () => {
  const source = `transmission "memory-demo" {
    title: "Memory Demo"
    engram clarityCard {
      value: "A pure compiler API should not need filesystem output."
      purpose: "prove AML can compile source strings in memory"
      memory_role: "test_node"
      user_effect: "clarity"
      attention_cost: 2
      restoration_value: 8
    }
  }`;

  const result = compileSource(source);
  assert.ok(result.tokens.length > 0);
  assert.ok(result.renderDecisions.length > 0);
  assert.equal(typeof result.html, "string");
  assert.ok(result.html.length > 0);
});
