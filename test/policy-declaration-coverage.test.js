import test from "node:test";
import assert from "node:assert/strict";

import { compileSource, executeAccountableIntent, policyFromProfile,
  replayExecutionReceipt, verifyExecutionReceipt } from "../index.js";

const timestamp = "2030-01-01T00:00:00.000Z";

const controls = [
  {
    name: "consent", declaration: "consent_required: required",
    profile: "calm_default", denied: { consent_granted: false },
    allowed: { consent_granted: true }
  },
  {
    name: "privacy", declaration: "collects_personal_data: yes",
    profile: "privacy_first", denied: { privacy_consent: false },
    allowed: { privacy_consent: true }
  },
  {
    name: "motion", declaration: "motion_required: true",
    profile: "accessibility_first", denied: { prefers_reduced_motion: true },
    allowed: { prefers_reduced_motion: false }
  },
  {
    name: "contrast", declaration: "contrast_safe: false",
    profile: "accessibility_first", denied: { high_contrast_required: true },
    allowed: { high_contrast_required: false }
  },
  {
    name: "cognitive load", declaration: "cognitive_load: 5",
    profile: "accessibility_first", denied: { max_cognitive_load: 2 },
    allowed: { max_cognitive_load: 5 }
  }
];

for (const control of controls) {
  test(`${control.name} declaration alone receives a decision and governs HTML`, () => {
    const marker = `CONTROL_${control.name.replaceAll(" ", "_").toUpperCase()}`;
    const source = `transmission "controls" {
      engram "panel" {
        value: "${marker}"
        ${control.declaration}
      }
    }`;
    const compile = context => compileSource(source, {
      timestamp, policy: policyFromProfile(control.profile), context
    });

    const denied = compile(control.denied);
    assert.equal(denied.renderDecisions.length, 1);
    assert.equal(denied.renderDecisions[0].render_allowed, false);
    assert.doesNotMatch(denied.html, new RegExp(marker));
    assert.match(denied.html, /data-aml-suppressed="true"/);

    const allowed = compile(control.allowed);
    assert.equal(allowed.renderDecisions.length, 1);
    assert.equal(allowed.renderDecisions[0].render_allowed, true);
    assert.match(allowed.html, new RegExp(marker));
  });
}

test("a consent-only parent suppresses unannotated descendants", () => {
  const result = compileSource(`transmission "nested" {
    coherence_gate "boundary" {
      consent_required: required
      engram "inside" { value: "NESTED_PRIVATE_9381" }
    }
  }`, { timestamp, policy: policyFromProfile("calm_default"),
    context: { consent_granted: false } });
  assert.deepEqual(result.renderDecisions.map(({ identifier, render_allowed }) =>
    [identifier, render_allowed]), [["boundary", false], ["inside", true]]);
  assert.doesNotMatch(result.html, /NESTED_PRIVATE_9381/);
});

test("control-only suppression survives receipt verification and replay", () => {
  const receipt = executeAccountableIntent({ transmission: "receipt_controls", nodes: [
    { type: "engram", identifier: "consented", properties: {
      value: "PRIVATE_RECEIPT_9842", consent_required: "required"
    } },
    { type: "engram", identifier: "public", properties: {
      value: "PUBLIC_RECEIPT_5317", consent_required: false
    } }
  ] }, { timestamp, profile: "calm_default", context: { consent_granted: false } });
  assert.deepEqual(receipt.selected_render.decisions.map(({ render_allowed }) => render_allowed),
    [false, true]);
  assert.doesNotMatch(receipt.selected_render.html, /PRIVATE_RECEIPT_9842/);
  assert.match(receipt.selected_render.html, /PUBLIC_RECEIPT_5317/);
  assert.equal(verifyExecutionReceipt(receipt).verified, true);
  assert.equal(replayExecutionReceipt(receipt).verified, true);
});
