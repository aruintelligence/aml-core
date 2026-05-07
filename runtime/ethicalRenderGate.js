export function ethicalRenderGate(element){

  const attention_cost =
    (
      element.animation_intensity * 0.20 +
      element.cognitive_load * 0.30 +
      element.interaction_interruptions * 0.25 +
      element.reading_complexity * 0.15 +
      element.visual_noise * 0.10
    );

  const restoration_value =
    (
      element.clarity * 0.30 +
      element.usefulness * 0.25 +
      element.emotional_regulation * 0.20 +
      element.continuity * 0.15 +
      element.aesthetic_coherence * 0.10
    );

  const render_allowed =
    restoration_value >= attention_cost;

  return {

    attention_cost,

    restoration_value,

    render_allowed,

    fallback_triggered:
      !render_allowed,

    timestamp:
      new Date().toISOString()
  };
}
