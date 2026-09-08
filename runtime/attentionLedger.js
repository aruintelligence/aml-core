// runtime/attentionLedger.js
// ĀML v1.3 — cumulative session attention accounting.

export function createAttentionLedger(initialBudget = Infinity, options = {}) {
  if (typeof initialBudget !== "number" || Number.isNaN(initialBudget) || initialBudget < 0) {
    throw new TypeError("Initial attention budget must be a non-negative number.");
  }
  return {
    protocol: "ĀML Attention Ledger",
    version: "1.0",
    session_id: options.session_id || null,
    initial_budget: initialBudget,
    consumed: 0,
    remaining: initialBudget,
    entries: []
  };
}

export function consumeAttention(ledger, amount, metadata = {}) {
  if (!ledger || ledger.protocol !== "ĀML Attention Ledger") throw new Error("Invalid ĀML attention ledger.");
  if (typeof amount !== "number" || !Number.isFinite(amount) || amount < 0) throw new TypeError("Attention amount must be a finite non-negative number.");

  const before = ledger.remaining;
  const allowed = amount <= before;
  const consumed = allowed ? amount : 0;
  ledger.consumed += consumed;
  ledger.remaining = Number.isFinite(ledger.initial_budget) ? Math.max(0, before - consumed) : Infinity;

  const entry = {
    sequence: ledger.entries.length,
    amount_requested: amount,
    amount_consumed: consumed,
    allowed,
    budget_before: before,
    budget_after: ledger.remaining,
    metadata: structuredClone(metadata)
  };
  ledger.entries.push(entry);
  return entry;
}

export function accountRenderDecisions(ledger, decisions, options = {}) {
  if (!Array.isArray(decisions)) throw new TypeError("Render decisions must be an array.");
  const results = [];
  for (const decision of decisions) {
    if (!decision.render_allowed && options.consume_suppressed !== true) {
      results.push({
        skipped: true,
        reason: "decision suppressed",
        identifier: decision.identifier || decision.name || null,
        budget_after: ledger.remaining
      });
      continue;
    }
    const amount = typeof decision.attention_cost === "number" ? decision.attention_cost : 0;
    results.push(consumeAttention(ledger, amount, {
      identifier: decision.identifier || decision.name || null,
      node_type: decision.node_type,
      policy_id: decision.policy_id,
      render_allowed: decision.render_allowed
    }));
  }
  return results;
}

export function attentionContext(ledger, extra = {}) {
  if (!ledger || ledger.protocol !== "ĀML Attention Ledger") throw new Error("Invalid ĀML attention ledger.");
  return {
    ...structuredClone(extra),
    attention_budget_remaining: ledger.remaining,
    attention_budget_consumed: ledger.consumed,
    attention_budget_initial: ledger.initial_budget
  };
}
