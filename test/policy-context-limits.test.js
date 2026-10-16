import assert from "node:assert/strict";
import test from "node:test";
import { BUILTIN_POLICIES, compileSource, executeAccountableIntent,
  policyFromProfile, replayExecutionReceipt, simulatePolicies,
  verifyExecutionReceipt } from "../index.js";

const timestamp = "2030-01-01T00:00:00.000Z";
const source = `transmission "limits" {
  message "offer" { content: "LIMITED_OFFER_5287" attention_cost: 2 restoration_value: 8 cognitive_load: 2 }
}`;
const intent = { transmission: "limits", nodes: [{ type: "message", identifier: "offer",
  properties: { content: "LIMITED_OFFER_5287", attention_cost: 2,
    restoration_value: 8, cognitive_load: 2 } }] };

test("malformed numeric context limits fail before rendering or issuing a receipt", () => {
  for (const key of ["attention_budget_remaining", "attention_budget_initial", "max_cognitive_load"]) {
    for (const value of ["0", -1, NaN, Infinity, false, undefined]) {
      const context = { [key]: value };
      const error = new RegExp(`context\\.${key} must be a non-negative finite number or null`);
      assert.throws(() => compileSource(source, { timestamp, policy: policyFromProfile("human_first"), context }), error);
      assert.throws(() => simulatePolicies(source, ["restorative_v1"], { timestamp, context }), error);
      assert.throws(() => executeAccountableIntent(intent, { timestamp, profile: "human_first", context }), error);
    }
  }
  assert.throws(() => compileSource(source, { context: [] }), /Policy context must be an object/);
  assert.throws(() => executeAccountableIntent(intent, { context: false }), /Policy context must be an object/);
  const inherited = Object.create({ attention_budget_remaining: 0 });
  assert.throws(() => compileSource(source, { context: inherited }), /must be an own property/);
});

test("direct built-in budget and cognitive guards reject malformed limits", () => {
  const element = { attention_cost: 2, restoration_value: 8 };
  for (const policy of [BUILTIN_POLICIES.session_attention_budget_v1,
    BUILTIN_POLICIES.cognitive_load_guard_v1]) {
    assert.throws(() => policy.evaluate(element, { context: { attention_budget_remaining: "0" } }),
      /context\.attention_budget_remaining/);
    assert.throws(() => policy.evaluate(element, { context: { max_cognitive_load: "0" } }),
      /context\.max_cognitive_load/);
  }
});

test("zero limits suppress, finite limits account, and null remains unbounded", () => {
  for (const context of [{ attention_budget_remaining: 0 },
    { attention_budget_initial: 0 }, { max_cognitive_load: 0 }]) {
    const receipt = executeAccountableIntent(intent, { timestamp, profile: "human_first", context });
    assert.equal(receipt.selected_render.allowed, 0);
    assert.doesNotMatch(receipt.selected_render.html, /LIMITED_OFFER_5287/);
    assert.equal(verifyExecutionReceipt(receipt).verified, true);
    assert.equal(replayExecutionReceipt(receipt).verified, true);
  }

  const finite = executeAccountableIntent(intent, { timestamp, profile: "human_first",
    context: { attention_budget_remaining: 3, attention_budget_initial: 10,
      max_cognitive_load: 2 } });
  assert.equal(finite.selected_render.allowed, 1);
  assert.equal(finite.attention_ledger.initial_budget, 3);
  assert.deepEqual([finite.attention_ledger.consumed, finite.attention_ledger.remaining], [2, 1]);
  assert.equal(replayExecutionReceipt(finite).verified, true);

  const fallback = executeAccountableIntent(intent, { timestamp, profile: "human_first",
    context: { attention_budget_remaining: null, attention_budget_initial: 3 } });
  assert.equal(fallback.attention_ledger.initial_budget, 3);
  assert.equal(fallback.attention_ledger.remaining, 1);

  const receipt = executeAccountableIntent(intent, { timestamp, profile: "human_first",
    context: { attention_budget_remaining: null, attention_budget_initial: null,
      max_cognitive_load: null } });
  assert.equal(receipt.selected_render.allowed, 1);
  assert.equal(receipt.attention_ledger.initial_budget, null);
  assert.match(receipt.selected_render.html, /LIMITED_OFFER_5287/);
  assert.equal(replayExecutionReceipt(receipt).verified, true);
});
