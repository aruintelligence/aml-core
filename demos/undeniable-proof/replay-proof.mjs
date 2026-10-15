import assert from "node:assert/strict";
import fs from "node:fs";
import { compileSource, executeAccountableIntent, replayExecutionReceipt,
  policyFromProfile, verifyExecutionReceipt } from "../../index.js";

const intent = JSON.parse(fs.readFileSync(new URL("./intent.json", import.meta.url), "utf8"));
const options = {
  timestamp: "2026-09-08T06:15:00.000Z",
  stream_id: "aml-undeniable-proof-0001",
  profile: "calm_default",
  context: {
    session_id: "aml-undeniable-proof-session",
    attention_budget_initial: 10,
    consent_granted: false
  }
};

const first = executeAccountableIntent(intent, options);
const second = executeAccountableIntent(intent, options);

const firstVerification = verifyExecutionReceipt(first);
const secondVerification = verifyExecutionReceipt(second);

assert.equal(firstVerification.verified, true, "first receipt must verify");
assert.equal(secondVerification.verified, true, "second receipt must verify");
assert.equal(first.receipt_sha256, second.receipt_sha256, "replayed receipt hashes must match exactly");
assert.equal(first.decision_sha256, second.decision_sha256, "replayed decision hashes must match exactly");
assert.equal(first.output_sha256, second.output_sha256, "replayed output hashes must match exactly");
assert.deepEqual(first, second, "fixed-input replay must produce an identical receipt object");

const countdown = first.selected_render.decisions.find(item => item.identifier === "countdown_pressure");
const purchase = first.selected_render.decisions.find(item => item.identifier === "purchase_action");
assert.equal(countdown?.render_allowed, false, "countdown pressure must be suppressed");
assert.equal(purchase?.render_allowed, true, "ordinary purchase action must remain allowed");
assert.match(first.selected_render.html,
  /<section hidden data-aml-suppressed="true" data-render-allowed="false">/,
  "the denied node must be suppressed in the actual HTML");
assert.doesNotMatch(first.selected_render.html,
  /countdown_pressure|Increase urgency during checkout/,
  "the denied node's metadata must not appear in HTML");
assert.match(first.selected_render.html,
  /data-aml-identifier="purchase_action"[^>]*data-render-allowed="true"[^>]*>/,
  "the allowed sibling must appear in the actual HTML");
assert.equal((first.selected_render.html.match(/data-aml-suppressed="true"/g) || []).length, 1,
  "the allowed sibling must not inherit the denied node's decision");

// Policy-only declarations must be evaluated even without a purpose or score.
const controlOnly = executeAccountableIntent({ transmission: "consent_only", nodes: [
  { type: "engram", identifier: "private", properties: {
    value: "PRIVATE_PROOF_2841", consent_required: "required"
  } },
  { type: "engram", identifier: "public", properties: {
    value: "PUBLIC_PROOF_5913", consent_required: false
  } }
] }, options);
assert.deepEqual(controlOnly.selected_render.decisions.map(item => item.render_allowed),
  [false, true], "the control-only nodes must both receive their own decisions");
assert.doesNotMatch(controlOnly.selected_render.html, /PRIVATE_PROOF_2841/,
  "the denied content must not appear in HTML");
assert.match(controlOnly.selected_render.html, /<h2>PUBLIC_PROOF_5913<\/h2>/,
  "the permitted content must appear in HTML");
assert.equal(verifyExecutionReceipt(controlOnly).verified, true);
assert.equal(replayExecutionReceipt(controlOnly).verified, true);

let barePolicyCalls = 0;
const bare = compileSource(`transmission "bare_proof" {
  engram "private" { value: "BARE_PRIVATE_PROOF_7164" }
}`, { timestamp: options.timestamp, policy(_element, { node }) {
  barePolicyCalls += 1;
  assert.equal(node.identifier, "private");
  return { render_allowed: false, attention_cost: 1, restoration_value: 1 };
} });
assert.equal(barePolicyCalls, 1, "a bare content node must reach the custom policy");
assert.equal(bare.renderDecisions[0]?.render_allowed, false);
assert.doesNotMatch(bare.html, /BARE_PRIVATE_PROOF_7164/,
  "custom-policy denial must remove bare content from HTML");

const nested = executeAccountableIntent({ transmission: "nested_budget_proof", nodes: [
  { type: "coherence_gate", identifier: "denied_parent", properties: {
    purpose: "Requires consent", attention_cost: 1, restoration_value: 8,
    consent_required: "required"
  }, children: [{ type: "engram", identifier: "hidden_child", properties: {
    value: "HIDDEN_BUDGET_PROOF_6721", purpose: "Hidden child",
    attention_cost: 4, restoration_value: 8
  } }] },
  { type: "engram", identifier: "visible_sibling", properties: {
    value: "VISIBLE_BUDGET_PROOF_4328", purpose: "Useful sibling",
    attention_cost: 2, restoration_value: 8
  } }
] }, { ...options, context: { consent_granted: false, attention_budget_remaining: 5 } });
assert.deepEqual(nested.selected_render.decisions.map(item => item.render_allowed),
  [false, false, true], "a denied parent must suppress its child before accounting");
assert.deepEqual(nested.attention_ledger.entries.map(entry => entry.metadata.identifier),
  ["visible_sibling"], "the hidden child must not consume attention");
assert.equal(nested.attention_ledger.consumed, 2);
assert.doesNotMatch(nested.selected_render.html, /HIDDEN_BUDGET_PROOF_6721/);
assert.match(nested.selected_render.html, /VISIBLE_BUDGET_PROOF_4328/);
const directNested = compileSource(nested.aml_source, {
  timestamp: options.timestamp, policy: policyFromProfile("calm_default"),
  context: { consent_granted: false, attention_budget_remaining: 5 }
});
assert.deepEqual(directNested.renderDecisions.map(item => item.render_allowed),
  [false, false, true], "direct compilation must count the hidden child as suppressed");
assert.equal(verifyExecutionReceipt(nested).verified, true);
assert.equal(replayExecutionReceipt(nested).verified, true);

console.log(JSON.stringify({
  proof: "PASS",
  receipt_sha256: first.receipt_sha256,
  decision_sha256: first.decision_sha256,
  output_sha256: first.output_sha256,
  suppressed: first.selected_render.suppressed,
  allowed: first.selected_render.allowed,
  control_only_consent: {
    receipt_sha256: controlOnly.receipt_sha256,
    suppressed: controlOnly.selected_render.suppressed,
    allowed: controlOnly.selected_render.allowed,
    replay_verified: true
  },
  unannotated_custom_policy: { calls: barePolicyCalls, suppressed: 1 },
  nested_attention: {
    receipt_sha256: nested.receipt_sha256,
    suppressed: nested.selected_render.suppressed,
    allowed: nested.selected_render.allowed,
    consumed: nested.attention_ledger.consumed,
    replay_verified: true
  }
}, null, 2));
