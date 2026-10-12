import assert from "node:assert/strict";
import test from "node:test";
import { compileSourceBrowser } from "../docs/aml-browser.js";
import { verifiedGateEvent } from "../docs/playground-live.js";

const source = `transmission "comparison" {
  engram urgent { value: "Buy now" purpose: "Create urgency" attention_cost: 5 restoration_value: 1 }
  engram clear { value: "Review terms" purpose: "Explain the offer" attention_cost: 5 restoration_value: 5 }
}`;
const [suppressed, allowed] = compileSourceBrowser(source).renderDecisions;

test("the live gate must match each compiled decision and its own declaration", () => {
  const urgent = { purpose: "Create urgency", attention: 5, restoration: 1 };
  const clear = { purpose: "Explain the offer", attention: 5, restoration: 5 };
  const event = (declaration, renderAllowed) => ({
    ok: true, purpose: declaration.purpose, attention_cost: declaration.attention,
    restoration_value: declaration.restoration, deployment_mode: "enforce",
    failure_mode: "closed", render_allowed: renderAllowed, effective_rendered: renderAllowed
  });
  assert.equal(verifiedGateEvent(event(urgent, false), suppressed, urgent, true), true);
  assert.equal(verifiedGateEvent(event(clear, true), allowed, clear, false), true);
  assert.equal(verifiedGateEvent(event(urgent, false), allowed, clear, true), false);
  assert.equal(verifiedGateEvent(event(clear, true), suppressed, urgent, false), false);
  assert.equal(verifiedGateEvent({ ...event(clear, true), deployment_mode: "shadow" }, allowed, clear, false), false);
  assert.equal(verifiedGateEvent({ ...event(clear, true), restoration_value: 1 }, allowed, clear, false), false);
  assert.equal(verifiedGateEvent({ ...event(clear, true), ok: false }, allowed, clear, false), false);
  assert.equal(verifiedGateEvent(event(clear, true), allowed, clear, true), false);
  assert.equal(verifiedGateEvent(null, allowed, clear, false), false);
});
