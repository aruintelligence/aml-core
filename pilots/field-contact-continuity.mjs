// A scoped field-study guard over observed contact links. It cannot infer
// unseen viewports or guarantee that a real phone or email service responds.
export function evaluateContactContinuity(observation, labels, { adversarial = false } = {}) {
  const elements = new Map(observation.elements.map(element => [element.id, element]));
  const choices = labels.candidates.map(candidate => ({ ...candidate,
    restoration_value: adversarial && candidate.element_id === labels.adversarial_change.element_id ?
      labels.adversarial_change.restoration_value : candidate.restoration_value }));
  if (elements.size !== observation.elements.length || choices.length !== elements.size ||
      new Set(choices.map(choice => choice.element_id)).size !== choices.length ||
      choices.some(choice => !elements.has(choice.element_id) ||
        !Number.isFinite(choice.attention_cost) || !Number.isFinite(choice.restoration_value))) {
    throw new Error("invalid_field_labels");
  }
  const decisions = choices.map(choice => ({ element_id: choice.element_id,
    decision: choice.restoration_value >= choice.attention_cost ? "allow" : "suppress",
    attention_cost: choice.attention_cost, restoration_value: choice.restoration_value }));
  const allowed = new Set(decisions.filter(row => row.decision === "allow").map(row => row.element_id));
  const screens = observation.screens.map(screen => {
    if (new Set(screen.visible).size !== screen.visible.length ||
        screen.visible.some(id => !elements.has(id))) throw new Error("invalid_field_observation");
    const visible = screen.visible.filter(id => allowed.has(id));
    const channels = Object.fromEntries(labels.required_visible_channels_per_observed_screen.map(channel =>
      [channel, visible.filter(id => elements.get(id).channel === channel).length]));
    const missing = Object.keys(channels).filter(channel => channels[channel] === 0);
    return { id: screen.id, visible_after_candidate: visible, channels, missing, continuity: missing.length ? "fail" : "pass" };
  });
  return { decisions, screens, continuity: screens.every(screen => screen.continuity === "pass") ? "pass" : "fail" };
}
