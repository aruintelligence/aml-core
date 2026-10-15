import test from "node:test";
import assert from "node:assert/strict";

import { compileSource, executeAccountableIntent, policyFromProfile,
  replayExecutionReceipt, verifyExecutionReceipt } from "../index.js";

const timestamp = "2030-01-01T00:00:00.000Z";

test("denied HTML omits metadata and content while allowed sibling metadata remains", () => {
  const result = compileSource(`transmission "privacy_case" {
    engram "DENIED_IDENTIFIER_7291" {
      value: "DENIED_VALUE_4628"
      purpose: "DENIED_PURPOSE_5917"
      memory_role: "DENIED_MEMORY_9156"
      user_effect: "DENIED_EFFECT_3652"
      attention_cost: 1
      restoration_value: 8
      consent_required: required
    }
    engram "ALLOWED_IDENTIFIER_7364" {
      value: "ALLOWED_VALUE_4682"
      purpose: "ALLOWED_PURPOSE_7319"
      attention_cost: 1
      restoration_value: 8
    }
  }`, { timestamp, policy: policyFromProfile("calm_default"),
    context: { consent_granted: false } });

  assert.deepEqual(result.renderDecisions.map(({ render_allowed }) => render_allowed), [false, true]);
  assert.equal(result.renderDecisions[0].identifier, "DENIED_IDENTIFIER_7291");
  assert.equal(result.renderDecisions[0].purpose, "DENIED_PURPOSE_5917");
  assert.equal(result.renderDecisions[0].memory_role, "DENIED_MEMORY_9156");
  assert.equal(result.renderDecisions[0].user_effect, "DENIED_EFFECT_3652");
  for (const marker of ["DENIED_IDENTIFIER_7291", "DENIED_VALUE_4628",
    "DENIED_PURPOSE_5917", "DENIED_MEMORY_9156", "DENIED_EFFECT_3652"]) {
    assert.equal(result.html.includes(marker), false, `${marker} leaked into HTML`);
  }
  assert.equal((result.html.match(/data-aml-suppressed="true"/g) || []).length, 1);
  assert.match(result.html,
    /<section hidden data-aml-suppressed="true" data-render-allowed="false">/);
  assert.match(result.html, /data-aml-identifier="ALLOWED_IDENTIFIER_7364"/);
  assert.match(result.html, /data-purpose="ALLOWED_PURPOSE_7319"/);
  assert.match(result.html, /<h2>ALLOWED_VALUE_4682<\/h2>/);
});

test("a denied ancestor and its child leave no node metadata in replayable HTML", () => {
  const receipt = executeAccountableIntent({ transmission: "nested_privacy", nodes: [
    { type: "coherence_gate", identifier: "DENIED_PARENT_2486", properties: {
      purpose: "DENIED_PARENT_PURPOSE_7618", attention_cost: 1,
      restoration_value: 8, consent_required: "required"
    }, children: [{ type: "engram", identifier: "HIDDEN_CHILD_7613", properties: {
      value: "HIDDEN_VALUE_1349", purpose: "HIDDEN_PURPOSE_4681",
      attention_cost: 1, restoration_value: 8
    } }] },
    { type: "engram", identifier: "VISIBLE_SIBLING_2907", properties: {
      value: "VISIBLE_VALUE_7493", purpose: "VISIBLE_PURPOSE_6824",
      attention_cost: 1, restoration_value: 8
    } }
  ] }, { timestamp, profile: "calm_default", context: { consent_granted: false } });

  assert.deepEqual(receipt.selected_render.decisions.map(({ render_allowed }) => render_allowed),
    [false, false, true]);
  const html = receipt.selected_render.html;
  for (const marker of ["DENIED_PARENT_2486", "DENIED_PARENT_PURPOSE_7618",
    "HIDDEN_CHILD_7613", "HIDDEN_VALUE_1349", "HIDDEN_PURPOSE_4681"]) {
    assert.equal(html.includes(marker), false, `${marker} leaked into HTML`);
  }
  assert.match(html, /data-aml-identifier="VISIBLE_SIBLING_2907"/);
  assert.match(html, /<h2>VISIBLE_VALUE_7493<\/h2>/);
  assert.equal(verifyExecutionReceipt(receipt).verified, true);
  assert.equal(replayExecutionReceipt(receipt).verified, true);
});

test("a denied transmission emits only the generic suppressed placeholder", () => {
  const result = compileSource(`transmission "ROOT_IDENTIFIER_9245" {
    purpose: "ROOT_PURPOSE_3179"
    consent_required: required
    engram "CHILD_IDENTIFIER_6837" { value: "CHILD_VALUE_7412" }
  }`, { timestamp, policy: policyFromProfile("calm_default"),
    context: { consent_granted: false } });

  assert.equal(result.renderDecisions[0].render_allowed, false);
  assert.equal(result.renderDecisions[0].identifier, "ROOT_IDENTIFIER_9245");
  for (const marker of ["ROOT_IDENTIFIER_9245", "ROOT_PURPOSE_3179",
    "CHILD_IDENTIFIER_6837", "CHILD_VALUE_7412"]) {
    assert.equal(result.html.includes(marker), false, `${marker} leaked into HTML`);
  }
  assert.equal((result.html.match(/data-aml-suppressed="true"/g) || []).length, 1);
});
