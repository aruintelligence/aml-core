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

function stableStringify(value) {
  if (Array.isArray(value)) return `[${value.map(stableStringify).join(",")}]`;
  if (value && typeof value === "object") {
    return `{${Object.keys(value).sort().filter(key => value[key] !== undefined).map(key => `${JSON.stringify(key)}:${stableStringify(value[key])}`).join(",")}}`;
  }
  return JSON.stringify(value);
}

function sha256(value) {
  return crypto.createHash("sha256").update(typeof value === "string" ? value : stableStringify(value)).digest("hex");
}

function refreshOuterReceiptHash(receipt) {
  const { receipt_sha256, signature, ...payload } = receipt;
  receipt.receipt_sha256 = sha256(payload);
  return receipt;
}

function freshReceipt() {
  return executeAccountableIntent(intent, {
    timestamp,
    profile: "calm_default",
    context: { consent_granted: true }
  });
}

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
  const receipt = freshReceipt();

  assert.equal(receipt.protocol, "ĀML Accountable Execution Receipt");
  assert.equal(receipt.profile.id, "calm_default");
  assert.equal(receipt.simulations.policy_count, 2);
  assert.equal(receipt.selected_render.suppressed, 0);
  assert.equal(verifyExecutionReceipt(receipt).verified, true);
});

test("default accountable receipt survives a JSON serialization round trip", () => {
  const receipt = freshReceipt();

  assert.equal(receipt.attention_ledger.initial_budget, null);
  assert.equal(receipt.attention_ledger.remaining, null);

  const roundTripped = JSON.parse(JSON.stringify(receipt));
  assert.equal(roundTripped.attention_ledger.initial_budget, null);
  assert.equal(roundTripped.attention_ledger.remaining, null);
  assert.equal(verifyExecutionReceipt(roundTripped).verified, true);
});

test("execution receipt verification detects mutation", () => {
  const receipt = freshReceipt();
  receipt.context.consent_granted = false;
  assert.equal(verifyExecutionReceipt(receipt).verified, false);
});

test("receipt verification rejects re-hashed intent binding mismatch", () => {
  const receipt = freshReceipt();
  receipt.intent.nodes[0].identifier = "tamperedIdentifier";
  refreshOuterReceiptHash(receipt);

  const verification = verifyExecutionReceipt(receipt);
  assert.equal(verification.receipt_hash_valid, true);
  assert.equal(verification.intent_binding_valid, false);
  assert.equal(verification.verified, false);
});

test("receipt verification rejects re-hashed AML source binding mismatch", () => {
  const receipt = freshReceipt();
  receipt.aml_source += "\n// tampered";
  refreshOuterReceiptHash(receipt);

  const verification = verifyExecutionReceipt(receipt);
  assert.equal(verification.receipt_hash_valid, true);
  assert.equal(verification.aml_binding_valid, false);
  assert.equal(verification.verified, false);
});

test("receipt verification rejects re-hashed simulation binding mismatch", () => {
  const receipt = freshReceipt();
  receipt.simulations.policy_count += 1;
  refreshOuterReceiptHash(receipt);

  const verification = verifyExecutionReceipt(receipt);
  assert.equal(verification.receipt_hash_valid, true);
  assert.equal(verification.simulation_binding_valid, false);
  assert.equal(verification.verified, false);
});

test("receipt verification rejects re-hashed decision binding mismatch", () => {
  const receipt = freshReceipt();
  receipt.selected_render.decisions[0].render_allowed = !receipt.selected_render.decisions[0].render_allowed;
  refreshOuterReceiptHash(receipt);

  const verification = verifyExecutionReceipt(receipt);
  assert.equal(verification.receipt_hash_valid, true);
  assert.equal(verification.decision_binding_valid, false);
  assert.equal(verification.verified, false);
});

test("receipt verification rejects re-hashed output binding mismatch", () => {
  const receipt = freshReceipt();
  receipt.selected_render.html += "<!-- tampered but outer hash refreshed -->";
  refreshOuterReceiptHash(receipt);

  const verification = verifyExecutionReceipt(receipt);
  assert.equal(verification.receipt_hash_valid, true);
  assert.equal(verification.output_binding_valid, false);
  assert.equal(verification.verified, false);
});

test("receipt verification rejects re-hashed selected-render count mismatch", () => {
  const receipt = freshReceipt();
  receipt.selected_render.allowed += 1;
  refreshOuterReceiptHash(receipt);

  const verification = verifyExecutionReceipt(receipt);
  assert.equal(verification.receipt_hash_valid, true);
  assert.equal(verification.selected_render_counts_valid, false);
  assert.equal(verification.verified, false);
});

test("receipt verification rejects re-hashed audit verification flag mismatch", () => {
  const receipt = freshReceipt();
  receipt.runtime_audit_verified = !receipt.runtime_audit_verified;
  refreshOuterReceiptHash(receipt);

  const verification = verifyExecutionReceipt(receipt);
  assert.equal(verification.receipt_hash_valid, true);
  assert.equal(verification.runtime_audit_flag_valid, false);
  assert.equal(verification.verified, false);
});

test("receipt verification rejects a structurally invalid ledger even when its hashes are refreshed", () => {
  const receipt = freshReceipt();
  const entry = receipt.attention_ledger.entries[0];
  entry.allowed = false;
  receipt.attention_ledger_sha256 = sha256(receipt.attention_ledger);
  refreshOuterReceiptHash(receipt);

  const verification = verifyExecutionReceipt(receipt);
  assert.equal(verification.receipt_hash_valid, true);
  assert.equal(verification.attention_ledger_hash_valid, true);
  assert.equal(verification.attention_ledger_structure_valid, false);
  assert.equal(verification.verified, false);
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
  const receipt = freshReceipt();
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
  const receipt = freshReceipt();
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
  const receipt = freshReceipt();
  const signed = signExecutionReceipt(receipt, privateKeyPem, { timestamp });
  signed.selected_render.html += "<!-- mutated -->";
  assert.equal(verifySignedExecutionReceipt(signed).verified, false);
});
