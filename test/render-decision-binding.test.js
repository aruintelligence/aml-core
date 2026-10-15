import test from "node:test";
import assert from "node:assert/strict";

import { compileSource, executeAccountableIntent, replayExecutionReceipt,
  policyFromProfile, verifyExecutionReceipt } from "../index.js";
import { generateHTML } from "../compiler/htmlGenerator.js";

const timestamp = "2030-01-01T00:00:00.000Z";
const context = { consent_granted: false };

function compile(nodes) {
  return compileSource(`transmission "binding" {\n${nodes.join("\n")}\n}`, {
    timestamp, policy: policyFromProfile("calm_default"), context
  });
}

test("a consent denial cannot inherit a sibling engram's allow decision", () => {
  const result = compile([
    'engram "public" { value: "PUBLIC_2481" purpose: "Helpful" attention_cost: 1 restoration_value: 8 }',
    'engram "private" { value: "PRIVATE_7392" purpose: "Need consent" attention_cost: 1 restoration_value: 8 consent_required: required }'
  ]);
  assert.deepEqual(result.renderDecisions.map(({ identifier, render_allowed }) =>
    [identifier, render_allowed]), [["public", true], ["private", false]]);
  assert.match(result.html, /<h2>PUBLIC_2481<\/h2>/);
  assert.doesNotMatch(result.html, /PRIVATE_7392/);
  assert.match(result.html, /data-aml-identifier="private"[^>]*hidden data-aml-suppressed="true"/);

  assert.throws(() => generateHTML(result.amt, result.renderDecisions.slice(0, 1)),
    /does not match semantic node/);
  assert.throws(() => generateHTML(result.amt, [...result.renderDecisions, result.renderDecisions[1]]),
    /entries without semantic nodes/);
  assert.throws(() => generateHTML(result.amt, result.renderDecisions.slice().reverse()),
    /does not match semantic node/);
});

test("anonymous siblings with identical type retain distinct decisions", () => {
  const result = compile([
    'engram { value: "PRIVATE_4321" purpose: "Need consent" attention_cost: 1 restoration_value: 8 consent_required: required }',
    'engram { value: "PUBLIC_9842" purpose: "Helpful" attention_cost: 1 restoration_value: 8 }'
  ]);
  assert.deepEqual(result.renderDecisions.map(({ identifier, render_allowed }) =>
    [identifier, render_allowed]), [[null, false], [null, true]]);
  assert.doesNotMatch(result.html, /PRIVATE_4321/);
  assert.match(result.html, /<h2>PUBLIC_9842<\/h2>/);
  assert.equal((result.html.match(/data-aml-suppressed="true"/g) || []).length, 1);
});

test("cumulative attention denial stays suppressed in a verifiable receipt", () => {
  const intent = { transmission: "budget_binding", nodes: [
    { type: "engram", identifier: "first", properties: {
      value: "FIRST_5227", purpose: "Helpful first", attention_cost: 2, restoration_value: 8
    } },
    { type: "engram", identifier: "second", properties: {
      value: "SECOND_9391", purpose: "Helpful second", attention_cost: 2, restoration_value: 8
    } }
  ] };
  const receipt = executeAccountableIntent(intent, { timestamp, profile: "calm_default",
    context: { attention_budget_remaining: 3 } });
  assert.deepEqual(receipt.selected_render.decisions.map(({ render_allowed }) => render_allowed),
    [true, false]);
  assert.match(receipt.selected_render.html, /<h2>FIRST_5227<\/h2>/);
  assert.doesNotMatch(receipt.selected_render.html, /SECOND_9391/);
  assert.match(receipt.selected_render.html,
    /data-aml-identifier="second"[^>]*hidden data-aml-suppressed="true"/);
  assert.equal(verifyExecutionReceipt(receipt).verified, true);
  assert.equal(replayExecutionReceipt(receipt).verified, true);
});
