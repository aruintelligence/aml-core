import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";

import {
  executeAccountableIntent,
  verifyExecutionReceipt,
  signExecutionReceipt,
  verifySignedExecutionReceipt,
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
  assert.ok(profiles.some(item => item.id === "privacy_first"));
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

test("privacy-first profile suppresses personal-data collection without privacy consent", () => {
  const source = `transmission "privacy" {\n  engram "collector" {\n    purpose: "Personalized helper"\n    attention_cost: 1\n    restoration_value: 8\n    collects_personal_data: yes\n  }\n}\n`;
  const result = compileSource(source, {
    timestamp,
    policy: policyFromProfile("privacy_first"),
    context: { privacy_consent: false, attention_budget_remaining: 10 }
  });
  assert.equal(result.renderDecisions.at(-1).render_allowed, false);
});

test("session attention budget can suppress otherwise restorative content", () => {
  const source = `transmission "budget" {\n  engram "panel" {\n    purpose: "Helpful panel"\n    attention_cost: 4\n    restoration_value: 9\n  }\n}\n`;
  const result = compileSource(source, {
    timestamp,
    policy: policyFromProfile("strict_attention"),
    context: { consent_granted: true, attention_budget_remaining: 2 }
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

test("default accountable receipt survives a JSON serialization round trip", () => {
  const receipt = executeAccountableIntent(intent, {
    timestamp,
    profile: "calm_default",
    context: { consent_granted: true }
  });

  assert.equal(receipt.attention_ledger.initial_budget, null);
  assert.equal(receipt.attention_ledger.remaining, null);

  const roundTripped = JSON.parse(JSON.stringify(receipt));
  assert.equal(roundTripped.attention_ledger.initial_budget, null);
  assert.equal(roundTripped.attention_ledger.remaining, null);
  assert.equal(verifyExecutionReceipt(roundTripped).verified, true);
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

test("accountable execution receipts can be Ed25519 signed and verified", () => {
  const { privateKey } = crypto.generateKeyPairSync("ed25519");
  const privateKeyPem = privateKey.export({ type: "pkcs8", format: "pem" });
  const receipt = executeAccountableIntent(intent, {
    timestamp,
    profile: "calm_default",
    context: { consent_granted: true }
  });
  const signed = signExecutionReceipt(receipt, privateKeyPem, {
    timestamp,
    signer: "test-suite"
  });

  const verification = verifySignedExecutionReceipt(signed);
  assert.equal(verification.verified, true);
  assert.equal(verification.signer, "test-suite");
});

test("signed accountable receipt survives a JSON serialization round trip", () => {
  const { privateKey } = crypto.generateKeyPairSync("ed25519");
  const privateKeyPem = privateKey.export({ type: "pkcs8", format: "pem" });
  const receipt = executeAccountableIntent(intent, {
    timestamp,
    profile: "calm_default",
    context: { consent_granted: true }
  });
  const signed = signExecutionReceipt(receipt, privateKeyPem, {
    timestamp,
    signer: "round-trip-test"
  });

  const roundTripped = JSON.parse(JSON.stringify(signed));
  const verification = verifySignedExecutionReceipt(roundTripped);
  assert.equal(verification.verified, true);
  assert.equal(verification.signer, "round-trip-test");
});

test("signed receipt verification fails after receipt mutation", () => {
  const { privateKey } = crypto.generateKeyPairSync("ed25519");
  const privateKeyPem = privateKey.export({ type: "pkcs8", format: "pem" });
  const receipt = executeAccountableIntent(intent, {
    timestamp,
    profile: "calm_default",
    context: { consent_granted: true }
  });
  const signed = signExecutionReceipt(receipt, privateKeyPem, { timestamp });
  signed.selected_render.html += "<!-- mutated -->";
  assert.equal(verifySignedExecutionReceipt(signed).verified, false);
});
