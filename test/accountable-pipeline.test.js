import test from "node:test";
import assert from "node:assert/strict";

import {
  executeAccountableIntent,
  verifyExecutionReceipt,
  listPolicyProfiles,
  policyFromProfile,
  compileSource
} from "../index.js";

const intent = {
  transmission: "accountable_ai_demo",
  nodes: [
    {
      type: "engram",
      identifier: "assistantRecommendation",
      properties: {
        purpose: "Offer a recommendation only when it is useful and consented.",
        attention_cost: 2,
        restoration_value: 8,
        consent_required: "required"
      }
    }
  ]
};

const timestamp = "2030-01-01T00:00:00.000Z";

test("policy profiles are discoverable", () => {
  const profiles = listPolicyProfiles();
  assert.ok(profiles.some(item => item.id === "calm_default"));
  assert.ok(profiles.some(item => item.id === "strict_attention"));
});

test("profile composition suppresses consent-gated content without consent", () => {
  const source = `transmission "demo" {\n  engram "offer" {\n    purpose: "Useful offer"\n    attention_cost: 2\n    restoration_value: 8\n    consent_required: required\n  }\n}\n`;
  const result = compileSource(source, {
    timestamp,
    policy: policyFromProfile("calm_default"),
    context: { consent_granted: false }
  });
  assert.equal(result.renderDecisions.at(-1).render_allowed, false);
});

test("accountable AI pipeline emits a verifiable execution receipt", () => {
  const receipt = executeAccountableIntent(intent, {
    timestamp,
    profile: "calm_default",
    context: { consent_granted: true }
  });

  assert.equal(receipt.protocol, "ĀML Accountable Execution Receipt");
  assert.equal(receipt.profile.id, "calm_default");
  assert.equal(receipt.simulations.policy_count, 2);
  assert.equal(receipt.selected_render.suppressed, 0);
  assert.equal(verifyExecutionReceipt(receipt).verified, true);
});

test("execution receipt verification detects mutation", () => {
  const receipt = executeAccountableIntent(intent, {
    timestamp,
    profile: "calm_default",
    context: { consent_granted: true }
  });
  receipt.context.consent_granted = false;
  assert.equal(verifyExecutionReceipt(receipt).verified, false);
});

test("same AI intent produces different selected render when consent changes", () => {
  const denied = executeAccountableIntent(intent, {
    timestamp,
    profile: "calm_default",
    context: { consent_granted: false }
  });
  const granted = executeAccountableIntent(intent, {
    timestamp,
    profile: "calm_default",
    context: { consent_granted: true }
  });

  assert.ok(denied.selected_render.suppressed > granted.selected_render.suppressed);
});
