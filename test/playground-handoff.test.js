import assert from "node:assert/strict";
import test from "node:test";
import { compileSourceBrowser } from "../docs/aml-browser.js";
import { parseSharedIntegration } from "../docs/quickstart-core.js";
import { studioHandoffUrl, studioHandoffUrls } from "../docs/playground-handoff.js";

const playground = "https://aruintelligence.github.io/aml-core/playground.html#v=1&source=example";
const properties = {
  value: "Review the offer", purpose: "Invite a considered review",
  attention_cost: 5, restoration_value: 1
};
function compiled(overrides = {}) {
  return {
    renderDecisions: [{
      node_type: "EngramNode", identifier: "offerPrompt",
      purpose: properties.purpose, attention_cost: 5, restoration_value: 1
    }],
    amt: { root: [{
      type: "TransmissionNode", children: [{
        type: "EngramNode", identifier: "offerPrompt", properties, children: []
      }]
    }] },
    ...overrides
  };
}

test("one compiler decision hands its declaration to the live gate studio", () => {
  const source = `transmission "first_program" {
  engram offerPrompt {
    value: "Review the offer"
    purpose: "Invite a considered review"
    attention_cost: 5
    restoration_value: 1
  }
}`;
  const link = studioHandoffUrl(compileSourceBrowser(source), playground);
  assert.equal(new URL(link).pathname, "/aml-core/quickstart.html");
  assert.equal(new URL(link).search, "");
  assert.deepEqual(parseSharedIntegration(link), {
    purpose: properties.purpose, label: properties.value,
    attention: 5, restoration: 1, mode: "enforce"
  });
});

test("ambiguous or unrepresentable programs do not silently become a different gate", () => {
  const base = compiled();
  assert.equal(studioHandoffUrl({ ...base, renderDecisions: [...base.renderDecisions, base.renderDecisions[0]] }, playground), null);
  assert.equal(studioHandoffUrl({ ...base, renderDecisions: [{ ...base.renderDecisions[0], attention_cost: 4 }] }, playground), null);
  assert.equal(studioHandoffUrl({ ...base, amt: { root: [{ type: "EngramNode", identifier: "offerPrompt", properties: { ...properties, value: "x".repeat(121) } }] } }, playground), null);
  assert.equal(studioHandoffUrl({ ...base, amt: { root: [{ type: "EngramNode", identifier: "offerPrompt", properties: { ...properties, restoration_value: 1.5 } }] } }, playground), null);
  assert.equal(studioHandoffUrl({ ...base, amt: { root: [] } }, playground), null);
});

test("a mixed program offers an exact live gate for each eligible decision", () => {
  const source = `transmission "compare_two_prompts" {
    engram urgentOffer {
      value: "Buy before the timer expires"
      purpose: "Prompt an immediate purchase"
      attention_cost: 5
      restoration_value: 1
    }
    engram clearDetails {
      value: "Review the full terms"
      purpose: "Help compare the offer"
      attention_cost: 5
      restoration_value: 5
    }
  }`;
  const result = compileSourceBrowser(source);
  assert.deepEqual(result.renderDecisions.map(item => item.render_allowed), [false, true]);
  const links = studioHandoffUrls(result, playground);
  assert.equal(links.length, 2);
  assert.deepEqual(links.map(parseSharedIntegration), [
    { purpose: "Prompt an immediate purchase", label: "Buy before the timer expires", attention: 5, restoration: 1, mode: "enforce" },
    { purpose: "Help compare the offer", label: "Review the full terms", attention: 5, restoration: 5, mode: "enforce" }
  ]);
  assert.equal(studioHandoffUrl(result, playground), null);
});

test("ambiguous matches suppress only those handoffs, preserving distinct engrams", () => {
  const original = compiled();
  const other = {
    type: "EngramNode", identifier: "clearDetails", children: [],
    properties: { value: "Review the full terms", purpose: "Help compare the offer", attention_cost: 5, restoration_value: 5 }
  };
  const secondDecision = {
    node_type: "EngramNode", identifier: "clearDetails", purpose: other.properties.purpose,
    attention_cost: 5, restoration_value: 5
  };
  const multiple = {
    ...original,
    renderDecisions: [...original.renderDecisions, secondDecision],
    amt: { root: [...original.amt.root, other] }
  };
  assert.deepEqual(studioHandoffUrls(multiple, playground).map(Boolean), [true, true]);
  const duplicate = { ...multiple, renderDecisions: [multiple.renderDecisions[0], multiple.renderDecisions[0], secondDecision] };
  assert.deepEqual(studioHandoffUrls(duplicate, playground).map(Boolean), [false, false, true]);
  const nonEngram = { ...multiple, renderDecisions: [{ ...multiple.renderDecisions[0], node_type: "ConditionNode" }, secondDecision] };
  assert.deepEqual(studioHandoffUrls(nonEngram, playground).map(Boolean), [false, true]);
});
