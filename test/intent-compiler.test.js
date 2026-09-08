import test from "node:test";
import assert from "node:assert/strict";

import { compileSource, generateAMLFromIntent } from "../index.js";

const intent = {
  transmission: "ai_generated_checkout",
  nodes: [
    {
      type: "engram",
      identifier: "CheckoutSummary",
      properties: {
        purpose: "Help the user confirm a purchase calmly.",
        attention_cost: 2.5,
        restoration_value: 6.5
      }
    }
  ]
};

test("machine intent deterministically generates AML source", () => {
  const one = generateAMLFromIntent(intent);
  const two = generateAMLFromIntent(intent);
  assert.equal(one, two);
  assert.match(one, /transmission "ai_generated_checkout"/);
  assert.match(one, /engram "CheckoutSummary"/);
});

test("generated AML compiles through the normal accountability pipeline", () => {
  const source = generateAMLFromIntent(intent);
  const result = compileSource(source, { timestamp: "1970-01-01T00:00:00.000Z" });
  assert.equal(result.renderDecisions.length, 1);
  assert.equal(result.renderDecisions[0].render_allowed, true);
  assert.equal(result.renderDecisions[0].purpose, "Help the user confirm a purchase calmly.");
});

test("invalid generated identifiers are rejected before source emission", () => {
  assert.throws(() => generateAMLFromIntent({
    nodes: [{ type: "bad node", properties: {} }]
  }), /valid ĀML identifier/);
});
