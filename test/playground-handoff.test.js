import assert from "node:assert/strict";
import test from "node:test";
import { compileSourceBrowser } from "../docs/aml-browser.js";
import { parseSharedIntegration } from "../docs/quickstart-core.js";
import { studioHandoffUrl } from "../docs/playground-handoff.js";

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
