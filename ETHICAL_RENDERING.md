// runtime/ethicalRenderGate.js
// ĀML_CORE v1.0 — EthicalRenderGate Runtime
// Evaluates whether an element should render based on restoration value vs attention cost.

export function ethicalRenderGate(element = {}) {
  const attention_cost =
    weightedAverage({
      animation_intensity: valueOrZero(element.animation_intensity) * 0.20,
      cognitive_load: valueOrZero(element.cognitive_load) * 0.30,
      interaction_interruptions: valueOrZero(element.interaction_interruptions) * 0.25,
      reading_complexity: valueOrZero(element.reading_complexity) * 0.15,
      visual_noise: valueOrZero(element.visual_noise) * 0.10
    });

  const restoration_value =
    weightedAverage({
      clarity: valueOrZero(element.clarity) * 0.30,
      usefulness: valueOrZero(element.usefulness) * 0.25,
      emotional_regulation: valueOrZero(element.emotional_regulation) * 0.20,
      continuity: valueOrZero(element.continuity) * 0.15,
      aesthetic_coherence: valueOrZero(element.aesthetic_coherence) * 0.10
    });

  const declared_attention_cost =
    typeof element.attention_cost === "number"
      ? element.attention_cost
      : attention_cost;

  const declared_restoration_value =
    typeof element.restoration_value === "number"
      ? element.restoration_value
      : restoration_value;

  const render_allowed =
    declared_restoration_value >= declared_attention_cost;

  return {
    purpose: element.purpose || null,
    memory_role: element.memory_role || null,
    user_effect: element.user_effect || null,

    attention_cost: round(declared_attention_cost),
    restoration_value: round(declared_restoration_value),

    calculated_attention_cost: round(attention_cost),
    calculated_restoration_value: round(restoration_value),

    render_allowed,
    fallback_triggered: !render_allowed,
    timestamp: new Date().toISOString()
  };
}

function weightedAverage(weightedValues) {
  return Object.values(weightedValues).reduce((sum, value) => sum + value, 0);
}

function valueOrZero(value) {
  return typeof value === "number" && Number.isFinite(value) ? value : 0;
}

function round(value) {
  return Math.round(value * 100) / 100;
}
