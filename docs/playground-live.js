// A live preview is valid only when the browser element emits the same decision
// for the exact declaration carried from one representable engram.
export function verifiedGateEvent(detail, decision, declaration, hidden) {
  const allowed = decision?.render_allowed;
  return typeof allowed === "boolean" && detail?.ok === true &&
    detail.purpose === declaration?.purpose &&
    detail.attention_cost === declaration?.attention &&
    detail.restoration_value === declaration?.restoration &&
    detail.deployment_mode === "enforce" && detail.failure_mode === "closed" &&
    detail.render_allowed === allowed && detail.effective_rendered === allowed &&
    hidden === !allowed;
}
