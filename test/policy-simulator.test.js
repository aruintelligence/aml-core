import test from "node:test";
import assert from "node:assert/strict";

import { simulatePolicies } from "../index.js";

const source = `transmission "counterfactual" {
  engram Card {
    purpose: "Compare policy outcomes."
    attention_cost: 5
    restoration_value: 5.5
  }
}`;

test("same AML source can be compared across policy regimes", () => {
  const result = simulatePolicies(source, ["restorative_v1", "attention_conservative_v1"]);
  assert.equal(result.policy_count, 2);
  assert.equal(result.decision_nodes, 1);
  assert.equal(result.runs[0].allowed, 1);
  assert.equal(result.runs[0].suppressed, 0);
  assert.equal(result.runs[1].allowed, 0);
  assert.equal(result.runs[1].suppressed, 1);
});
