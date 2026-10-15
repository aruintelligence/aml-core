import assert from "node:assert/strict";
import test from "node:test";
import { compileSource, executeAccountableIntent, policyFromProfile,
  replayExecutionReceipt, verifyExecutionReceipt } from "../index.js";

const timestamp = "2026-10-15T00:00:00.000Z";

test("permitted generic content is escaped while denied content stays out of HTML", () => {
  const result = compileSource(`transmission "content" {
    message "allowed" {
      content: "<script>alert(\\"x\\")</script> & clear"
      attention_cost: 0
      restoration_value: 1
    }
    message "denied" {
      content: "SECRET_MESSAGE_6291"
      consent_required: required
    }
    message "zero" { content: 0 }
  }`, { timestamp, policy: policyFromProfile("calm_default"),
    context: { consent_granted: false } });

  assert.deepEqual(result.renderDecisions.map(decision => decision.render_allowed),
    [true, false, true]);
  assert.match(result.html, /<p>&lt;script&gt;alert\(&quot;x&quot;\)&lt;\/script&gt; &amp; clear<\/p>/);
  assert.match(result.html, /<p>0<\/p>/);
  assert.doesNotMatch(result.html, /<script>|SECRET_MESSAGE_6291|data-aml-identifier="denied"/);
  assert.equal((result.html.match(/data-aml-suppressed="true"/g) || []).length, 1);
});

test("generic content survives execution receipt verification and replay", () => {
  const receipt = executeAccountableIntent({ transmission: "messages", nodes: [
    { type: "message", identifier: "allowed", properties: { content: "Continue & review" } },
    { type: "message", identifier: "denied", properties: {
      content: "PRIVATE_MESSAGE_7346", consent_required: "required"
    } }
  ] }, { timestamp, profile: "calm_default", context: { consent_granted: false } });

  assert.match(receipt.selected_render.html, /<p>Continue &amp; review<\/p>/);
  assert.doesNotMatch(receipt.selected_render.html, /PRIVATE_MESSAGE_7346/);
  assert.equal(receipt.selected_render.allowed, 1);
  assert.equal(receipt.selected_render.suppressed, 1);
  assert.equal(verifyExecutionReceipt(receipt).verified, true);
  assert.equal(replayExecutionReceipt(receipt).verified, true);
});
