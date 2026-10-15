import test from "node:test";
import assert from "node:assert/strict";

import { compileSource, executeAccountableIntent, policyFromProfile,
  replayExecutionReceipt, simulatePolicies, verifyExecutionReceipt } from "../index.js";
import { compileSourceBrowser } from "../docs/aml-browser.js";

const timestamp = "2030-01-01T00:00:00.000Z";

test("a denied parent suppresses child decisions and simulation counts, but not a sibling", () => {
  const source = `transmission "policy_tree" {
    coherence_gate "parent" {
      consent_required: required
      engram "child" { value: "HIDDEN_CHILD_9542" }
    }
    engram "sibling" { value: "VISIBLE_SIBLING_1653" }
  }`;
  const policy = policyFromProfile("calm_default");
  const options = { timestamp, policy, context: { consent_granted: false } };
  const compiled = compileSource(source, options);
  const decisions = compiled.renderDecisions;
  assert.deepEqual(decisions.map(({ identifier, render_allowed }) =>
    [identifier, render_allowed]), [["parent", false], ["child", false], ["sibling", true]]);
  assert.match(JSON.stringify(decisions[1].policy_rationale), /ancestor_render_gate_v1/);
  assert.equal(decisions[1].fallback_triggered, true);
  assert.doesNotMatch(compiled.html, /HIDDEN_CHILD_9542|data-aml-identifier="child"/);
  assert.match(compiled.html, /VISIBLE_SIBLING_1653/);

  const simulation = simulatePolicies(source, [policy], options).runs[0];
  assert.deepEqual([simulation.allowed, simulation.suppressed], [1, 2]);
  assert.deepEqual(simulation.decisions, decisions);
});

test("policy evaluation still visits every descendant and records its own denial", () => {
  const visited = [];
  const compiled = compileSource(`transmission "nested" {
    coherence_gate "parent" {
      engram "allowed_by_policy" { value: "HIDDEN_2754" }
      engram "denied_by_policy" { value: "HIDDEN_6172" }
    }
  }`, { timestamp, policy(_element, { node }) {
    visited.push(node.identifier);
    return { render_allowed: node.identifier === "allowed_by_policy",
      attention_cost: 1, restoration_value: 1, rationale: "independent policy result" };
  } });
  assert.deepEqual(visited, ["parent", "allowed_by_policy", "denied_by_policy"]);
  assert.deepEqual(compiled.renderDecisions.map(d => d.render_allowed), [false, false, false]);
  assert.match(JSON.stringify(compiled.renderDecisions[1].policy_rationale), /ancestor_render_gate_v1/);
  assert.equal(compiled.renderDecisions[2].policy_rationale, "independent policy result");
  assert.doesNotMatch(compiled.html, /HIDDEN_2754|HIDDEN_6172/);
});

test("a denied parent covers its child while receipt verification and replay remain valid", () => {
  const receipt = executeAccountableIntent({ transmission: "root_policy", nodes: [
    { type: "coherence_gate", identifier: "parent", properties: {
      consent_required: "required"
    }, children: [{ type: "engram", identifier: "grandchild", properties: {
      value: "HIDDEN_GRANDCHILD_3174"
    } }] },
    { type: "engram", identifier: "sibling", properties: {
      value: "VISIBLE_SIBLING_2815"
    } }
  ] }, { timestamp, profile: "calm_default", context: { consent_granted: false } });
  assert.deepEqual(receipt.selected_render.decisions.map(d => d.render_allowed),
    [false, false, true]);
  assert.deepEqual([receipt.selected_render.allowed, receipt.selected_render.suppressed], [1, 2]);
  assert.deepEqual(receipt.simulations.runs.find(run => run.policy === "consent_guard_v1")
    .decisions.map(d => d.render_allowed), [false, false, true]);
  assert.doesNotMatch(receipt.selected_render.html, /HIDDEN_GRANDCHILD_3174/);
  assert.match(receipt.selected_render.html, /VISIBLE_SIBLING_2815/);
  assert.equal(verifyExecutionReceipt(receipt).verified, true);
  assert.equal(replayExecutionReceipt(receipt).verified, true);
});

test("a denied transmission root suppresses all descendant decisions", () => {
  const source = `transmission "root" {
    consent_required: required
    coherence_gate "container" {
      engram "grandchild" { value: "HIDDEN_AT_ROOT_2984" }
    }
  }`;
  const compiled = compileSource(source, { timestamp, policy: policyFromProfile("calm_default"),
    context: { consent_granted: false } });
  assert.deepEqual(compiled.renderDecisions.map(d => d.render_allowed), [false, false, false]);
  assert.match(JSON.stringify(compiled.renderDecisions[1].policy_rationale), /ancestor_render_gate_v1/);
  assert.match(JSON.stringify(compiled.renderDecisions[2].policy_rationale), /ancestor_render_gate_v1/);
  assert.doesNotMatch(compiled.html, /HIDDEN_AT_ROOT_2984/);
});

test("browser decision flags match Node for a score-denied ancestor", () => {
  const source = `transmission "browser_tree" {
    coherence_gate "blocked" {
      attention_cost: 5
      restoration_value: 1
      engram "child" { attention_cost: 1 restoration_value: 8 }
    }
    engram "sibling" { attention_cost: 1 restoration_value: 8 }
  }`;
  const node = compileSource(source, { timestamp });
  const browser = compileSourceBrowser(source);
  assert.deepEqual(node.renderDecisions.map(d => d.render_allowed), [false, false, true]);
  assert.deepEqual(browser.renderDecisions.map(d => d.render_allowed), [false, false, true]);
  assert.deepEqual(browser.renderDecisions.map(d => d.fallback_triggered), [true, true, false]);
});
