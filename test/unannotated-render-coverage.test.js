import test from "node:test";
import assert from "node:assert/strict";

import { compileSource, executeAccountableIntent, replayExecutionReceipt,
  verifyExecutionReceipt } from "../index.js";
import { generateHTML } from "../compiler/htmlGenerator.js";
import { compileSourceBrowser } from "../docs/aml-browser.js";

const timestamp = "2030-01-01T00:00:00.000Z";
const source = `transmission "content" {
  engram "private" { value: "PRIVATE_BARE_8612" }
  mirror "echo" { speak: "PRIVATE_SPEAK_7415" reflect: "PRIVATE_REFLECT_9273" }
  engram "public" { value: "PUBLIC_BARE_2948" }
}`;

test("custom policy evaluates every HTML-producing block without optional metadata", () => {
  const visited = [];
  const result = compileSource(source, { timestamp, policy(_element, { node }) {
    visited.push(node.identifier);
    return { render_allowed: node.identifier === "public", attention_cost: 1,
      restoration_value: 1 };
  } });

  assert.deepEqual(visited, ["private", "echo", "public"]);
  assert.deepEqual(result.renderDecisions.map(({ identifier, render_allowed }) =>
    [identifier, render_allowed]), [["private", false], ["echo", false], ["public", true]]);
  assert.doesNotMatch(result.html, /PRIVATE_BARE_8612|PRIVATE_SPEAK_7415|PRIVATE_REFLECT_9273/);
  assert.match(result.html, /<h2>PUBLIC_BARE_2948<\/h2>/);
  assert.equal((result.html.match(/data-aml-suppressed="true"/g) || []).length, 2);
  assert.throws(() => generateHTML(result.amt, []), /does not match semantic node/);
});

test("a malformed custom policy cannot silently allow an unannotated block", () => {
  assert.throws(() => compileSource(source, { timestamp, policy: () => ({}) }),
    /must return render_allowed as a boolean/);
});

test("an unannotated wrapper's denial suppresses its children", () => {
  const nested = `transmission "nested" {
    coherence_gate "wrapper" {
      engram "inside" { value: "NESTED_BARE_4528" }
    }
  }`;
  const result = compileSource(nested, { timestamp, policy(_element, { node }) {
    return { render_allowed: node.identifier !== "wrapper", attention_cost: 1,
      restoration_value: 1 };
  } });
  assert.deepEqual(result.renderDecisions.map(({ identifier, render_allowed }) =>
    [identifier, render_allowed]), [["wrapper", false], ["inside", false]]);
  assert.match(JSON.stringify(result.renderDecisions[1].policy_rationale), /ancestor_render_gate_v1/);
  assert.doesNotMatch(result.html, /NESTED_BARE_4528/);
});

test("browser compiler records the same bare and declared control nodes", () => {
  const mixed = `transmission "mixed" {
    engram "private" { value: "PRIVATE_BARE_8612" }
    mirror "echo" { speak: "PRIVATE_SPEAK_7415" reflect: "PRIVATE_REFLECT_9273" }
    engram "public" { value: "PUBLIC_BARE_2948" }
    engram "consent" { value: "CONTROL_BARE_5129" consent_required: required }
  }`;
  const core = compileSource(mixed, { timestamp });
  const browser = compileSourceBrowser(mixed);
  const withoutRuntimeFields = decisions => decisions.map(
    ({ timestamp: _timestamp, policy_id: _policy, policy_rationale: _rationale, ...fields }) => fields
  );
  assert.deepEqual(withoutRuntimeFields(browser.renderDecisions),
    withoutRuntimeFields(core.renderDecisions));
  assert.deepEqual(core.renderDecisions.map(({ identifier }) => identifier),
    ["private", "echo", "public", "consent"]);
});

test("unannotated siblings consume the cumulative budget and replay their receipt", () => {
  const receipt = executeAccountableIntent({ transmission: "bare_budget", nodes: [
    { type: "engram", identifier: "first", properties: { value: "BARE_FIRST_9821" } },
    { type: "engram", identifier: "second", properties: { value: "BARE_SECOND_7183" } }
  ] }, { timestamp, profile: "calm_default", context: { attention_budget_remaining: 1.5 } });
  assert.deepEqual(receipt.selected_render.decisions.map(({ render_allowed }) => render_allowed),
    [true, false]);
  assert.match(receipt.selected_render.html, /BARE_FIRST_9821/);
  assert.doesNotMatch(receipt.selected_render.html, /BARE_SECOND_7183/);
  assert.equal(verifyExecutionReceipt(receipt).verified, true);
  assert.equal(replayExecutionReceipt(receipt).verified, true);
});
