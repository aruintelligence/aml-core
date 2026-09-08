import test from "node:test";
import assert from "node:assert/strict";
import { evaluateConformanceLevel, createConformanceClaim, verifyConformanceClaim } from "../index.js";

const verifiableCaps = [
  "meaning-tree",
  "render-decision",
  "execution-receipt",
  "view-meaning",
  "policy-passport",
  "content-addressed-bundle",
  "causal-execution-graph",
  "selective-disclosure"
];

test("conformance evaluator returns highest satisfied level", () => {
  assert.equal(evaluateConformanceLevel(verifiableCaps).level, "verifiable");
  assert.equal(evaluateConformanceLevel(["meaning-tree", "render-decision"]).level, "core");
});

test("conformance claim is hash bound to declared capabilities and versions", () => {
  const claim = createConformanceClaim({
    implementation: "example/runtime",
    implementation_version: "0.1.0",
    language_version: "1.3.0",
    wire_version: "1.0",
    capabilities: verifiableCaps,
    issued_at: "2026-01-01T00:00:00.000Z"
  });
  assert.equal(verifyConformanceClaim(claim).valid, true);

  const tampered = structuredClone(claim);
  tampered.capabilities.pop();
  assert.equal(verifyConformanceClaim(tampered).valid, false);
});
