import test from "node:test";
import assert from "node:assert/strict";
import { evaluateAgentUI, AML_AGENT_UI_ENVELOPE, AML_AGENT_UI_RESULT } from "../adapters/agent-ui.js";

test("agent UI adapter suppresses high-pressure component and allows restorative component", () => {
  const result = evaluateAgentUI({
    protocol: AML_AGENT_UI_ENVELOPE,
    surface_id: "generated_checkout",
    components: [
      {
        id: "pressure_cta",
        type: "button",
        props: { label: "Act now" },
        governance: {
          purpose: "Create urgency during checkout",
          attention_cost: 5,
          restoration_value: 1,
          consent_required: false
        }
      },
      {
        id: "help_text",
        type: "text",
        props: { text: "Review your choices before continuing." },
        governance: {
          purpose: "Help the user review the decision",
          attention_cost: 1,
          restoration_value: 3,
          consent_required: false
        }
      }
    ]
  }, {
    profile: "calm_default",
    timestamp: "2026-09-10T19:30:00.000Z"
  });

  assert.equal(result.protocol, AML_AGENT_UI_RESULT);
  assert.equal(result.total, 2);
  assert.equal(result.allowed, 1);
  assert.equal(result.suppressed, 1);
  assert.equal(result.errors, 0);
  assert.deepEqual(result.renderable_components.map((c) => c.id), ["help_text"]);
  assert.deepEqual(result.suppressed_components.map((c) => c.id), ["pressure_cta"]);
  assert.equal(result.decisions[0].aml_allowed, false);
  assert.equal(result.decisions[1].aml_allowed, true);
  assert.match(result.decisions[0].receipt_sha256, /^[a-f0-9]{64}$/);
  assert.match(result.decisions[1].receipt_sha256, /^[a-f0-9]{64}$/);
});

test("agent UI adapter fails closed on missing governance metadata", () => {
  assert.throws(() => evaluateAgentUI({
    protocol: AML_AGENT_UI_ENVELOPE,
    components: [{ id: "unsafe", type: "button", props: { label: "Continue" } }]
  }), /governance must be an object/);
});
