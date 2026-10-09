import test from "node:test";
import assert from "node:assert/strict";
import { evaluateDemo } from "../lib/demo.mjs";
import { verifyExecutionReceipt } from "aml-core";

test("Next.js example enforces the policy and exposes bound evidence", () => {
  const { result, verification, meaning, diff } = evaluateDemo();
  assert.equal(result.allowed, false);
  assert.equal(result.allowed_count, 1);
  assert.equal(result.denied_count, 1);
  assert.equal(verification.verified, true);
  assert.equal(meaning.summary.allowed, 1);
  assert.equal(meaning.summary.suppressed, 1);
  assert.equal(diff.added.filter(node => node.identifier === "pressure").length, 1);
  assert.equal(diff.identity_ambiguity_detected, false);
  const mutated = structuredClone(result.receipt);
  mutated.selected_render.html = "changed after evaluation";
  assert.equal(verifyExecutionReceipt(mutated).verified, false);
});
