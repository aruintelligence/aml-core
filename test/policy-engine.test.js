import test from "node:test";
import assert from "node:assert/strict";

import { compileSource, listPolicies } from "../index.js";

const source = `transmission "policy-test" {
  engram TestCard {
    purpose: "Test policy behavior."
    attention_cost: 5
    restoration_value: 5.5
  }
}`;

test("built-in policy registry is discoverable", () => {
  const ids = listPolicies().map(item => item.id);
  assert.ok(ids.includes("restorative_v1"));
  assert.ok(ids.includes("attention_conservative_v1"));
});

test("restorative policy allows restoration >= attention", () => {
  const result = compileSource(source, { timestamp: "1970-01-01T00:00:00.000Z" });
  const decision = result.renderDecisions[0];
  assert.equal(decision.policy_id, "restorative_v1");
  assert.equal(decision.render_allowed, true);
});

test("attention-conservative policy can suppress the same element", () => {
  const result = compileSource(source, {
    timestamp: "1970-01-01T00:00:00.000Z",
    policy: "attention_conservative_v1"
  });
  const decision = result.renderDecisions[0];
  assert.equal(decision.policy_id, "attention_conservative_v1");
  assert.equal(decision.render_allowed, false);
});

test("custom policy functions are supported", () => {
  const result = compileSource(source, {
    timestamp: "1970-01-01T00:00:00.000Z",
    policy(element) {
      return {
        policy_id: "always_allow_test",
        attention_cost: element.attention_cost,
        restoration_value: element.restoration_value,
        render_allowed: true,
        fallback_triggered: false,
        rationale: "test override"
      };
    }
  });
  assert.equal(result.renderDecisions[0].policy_id, "always_allow_test");
  assert.equal(result.renderDecisions[0].render_allowed, true);
});
