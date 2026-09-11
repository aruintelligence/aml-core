import { evaluateAgentUI, AML_AGENT_UI_ENVELOPE } from "../index.js";

const generatedSurface = {
  protocol: AML_AGENT_UI_ENVELOPE,
  surface_id: "agent_checkout_surface",
  components: [
    {
      id: "countdown",
      type: "banner",
      props: { text: "Only 04:59 left" },
      governance: {
        purpose: "Increase urgency during checkout",
        attention_cost: 5,
        restoration_value: 1,
        consent_required: false
      }
    },
    {
      id: "review",
      type: "button",
      props: { label: "Review choices" },
      governance: {
        purpose: "Let the user review the decision",
        attention_cost: 1,
        restoration_value: 3,
        consent_required: false
      }
    }
  ]
};

const result = evaluateAgentUI(generatedSurface, {
  profile: "calm_default",
  timestamp: "2026-09-10T19:30:00.000Z"
});

console.log(JSON.stringify({
  protocol: result.protocol,
  surface_id: result.surface_id,
  allowed: result.allowed,
  suppressed: result.suppressed,
  renderable_ids: result.renderable_components.map((component) => component.id),
  suppressed_ids: result.suppressed_components.map((component) => component.id),
  decisions: result.decisions
}, null, 2));
