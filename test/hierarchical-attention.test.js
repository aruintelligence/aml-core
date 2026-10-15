import test from "node:test";
import assert from "node:assert/strict";

import { enforceCumulativeAttentionBudget, executeAccountableIntent,
  replayExecutionReceipt, verifyExecutionReceipt } from "../index.js";

const timestamp = "2030-01-01T00:00:00.000Z";

function panel(identifier, value, attentionCost, children = [], extra = {}) {
  return { type: children.length ? "coherence_gate" : "engram", identifier,
    properties: { value, purpose: identifier, attention_cost: attentionCost,
      restoration_value: 8, ...extra }, children };
}

test("a hidden child does not spend budget or block a visible sibling", () => {
  const intent = { transmission: "consent_budget", nodes: [
    panel("blocked_parent", "", 1, [panel("hidden_child", "HIDDEN_CHILD_2891", 4)],
      { consent_required: "required" }),
    panel("visible_sibling", "VISIBLE_SIBLING_7193", 2)
  ] };
  const receipt = executeAccountableIntent(intent, { timestamp, profile: "calm_default",
    context: { consent_granted: false, attention_budget_remaining: 5 } });
  const decisions = receipt.selected_render.decisions;
  assert.deepEqual(decisions.map(({ identifier, render_allowed }) =>
    [identifier, render_allowed]), [
    ["blocked_parent", false], ["hidden_child", false], ["visible_sibling", true]
  ]);
  assert.match(JSON.stringify(decisions[1].policy_rationale), /ancestor_render_gate_v1/);
  assert.deepEqual(receipt.attention_ledger.entries.map(entry => entry.metadata.identifier),
    ["visible_sibling"]);
  assert.deepEqual([receipt.attention_ledger.consumed, receipt.attention_ledger.remaining], [2, 3]);
  assert.doesNotMatch(receipt.selected_render.html, /HIDDEN_CHILD_2891/);
  assert.match(receipt.selected_render.html, /VISIBLE_SIBLING_7193/);
  assert.deepEqual([receipt.selected_render.allowed, receipt.selected_render.suppressed], [1, 2]);
  assert.equal(verifyExecutionReceipt(receipt).verified, true);
  assert.equal(replayExecutionReceipt(receipt).verified, true);
});

test("a budget-denied ancestor cascades through multiple levels before charging siblings", () => {
  const intent = { transmission: "ancestor_budget", nodes: [
    panel("too_expensive", "", 4, [
      panel("middle", "", 1, [panel("grandchild", "HIDDEN_GRANDCHILD_8462", 2)])
    ]),
    panel("visible", "VISIBLE_AFTER_DENIAL_6024", 2)
  ] };
  const receipt = executeAccountableIntent(intent, { timestamp, profile: "calm_default",
    context: { attention_budget_remaining: 3 } });
  assert.deepEqual(receipt.selected_render.decisions.map(({ identifier, render_allowed }) =>
    [identifier, render_allowed]), [
    ["too_expensive", false], ["middle", false], ["grandchild", false], ["visible", true]
  ]);
  assert.deepEqual(receipt.attention_ledger.entries.map(entry =>
    [entry.metadata.identifier, entry.allowed]), [["too_expensive", false], ["visible", true]]);
  assert.deepEqual([receipt.attention_ledger.consumed, receipt.attention_ledger.remaining], [2, 1]);
  assert.doesNotMatch(receipt.selected_render.html, /HIDDEN_GRANDCHILD_8462/);
  assert.match(receipt.selected_render.html, /VISIBLE_AFTER_DENIAL_6024/);
  assert.equal(replayExecutionReceipt(receipt).verified, true);
});

test("an unbounded ledger still marks descendants of a denied parent suppressed", () => {
  const receipt = executeAccountableIntent({ transmission: "unbounded", nodes: [
    panel("parent", "", 1, [panel("child", "HIDDEN_UNBOUNDED_3917", 4)],
      { consent_required: "required" }),
    panel("sibling", "VISIBLE_UNBOUNDED_5172", 2)
  ] }, { timestamp, profile: "calm_default", context: { consent_granted: false } });
  assert.deepEqual(receipt.selected_render.decisions.map(item => item.render_allowed),
    [false, false, true]);
  assert.equal(receipt.attention_ledger.consumed, 2);
  assert.equal(receipt.attention_ledger.remaining, null);
  assert.doesNotMatch(receipt.selected_render.html, /HIDDEN_UNBOUNDED_3917/);
  assert.match(receipt.selected_render.html, /VISIBLE_UNBOUNDED_5172/);
});

test("public budget helper validates optional parent indices before accounting", () => {
  const decisions = [{ render_allowed: true, attention_cost: 1 },
    { render_allowed: true, attention_cost: 2 }];
  const sparse = Array(2);
  sparse[1] = 0;
  for (const parents of [[], [null, 1], ["0", null], [null, -1],
    [null, undefined], sparse]) {
    assert.throws(() => enforceCumulativeAttentionBudget(decisions, 3,
      { parent_decision_indices: parents }), /Parent decision indices/);
  }
  assert.equal(enforceCumulativeAttentionBudget(decisions, 3).ledger.consumed, 3);
});
