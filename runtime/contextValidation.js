// A malformed numeric limit must never become an absent limit. Null is an
// accepted absence marker used by attentionContext and JSON receipts.
const NUMERIC_LIMITS = [
  "attention_budget_remaining",
  "attention_budget_initial",
  "max_cognitive_load"
];

export function validatePolicyContext(context) {
  if (!context || typeof context !== "object" || Array.isArray(context)) {
    throw new TypeError("Policy context must be an object.");
  }
  for (const key of NUMERIC_LIMITS) {
    if (!(key in context)) continue;
    if (!Object.hasOwn(context, key)) {
      throw new TypeError(`context.${key} must be an own property.`);
    }
    const value = context[key];
    if (value !== null &&
        (typeof value !== "number" || !Number.isFinite(value) || value < 0)) {
      throw new TypeError(`context.${key} must be a non-negative finite number or null.`);
    }
  }
  return context;
}
