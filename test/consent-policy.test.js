import test from "node:test";
import assert from "node:assert/strict";

import { compileSource } from "../index.js";

const source = `transmission "consent" {
  engram SponsoredPanel {
    purpose: "Render only with explicit consent."
    consent_required: true
    attention_cost: 1
    restoration_value: 4
  }
}`;

test("consent-gated node is suppressed without runtime consent", () => {
  const result = compileSource(source, {
    timestamp: "1970-01-01T00:00:00.000Z",
    policy: "consent_guard_v1",
    context: { consent_granted: false }
  });
  assert.equal(result.renderDecisions[0].render_allowed, false);
  assert.match(result.renderDecisions[0].policy_rationale, /consent_required/);
});

test("same source is allowed when runtime consent is explicitly granted", () => {
  const result = compileSource(source, {
    timestamp: "1970-01-01T00:00:00.000Z",
    policy: "consent_guard_v1",
    context: { consent_granted: true }
  });
  assert.equal(result.renderDecisions[0].render_allowed, true);
});
