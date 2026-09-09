// runtime/attentionIntegrity.js
// ĀML v1.3 — consistency verification for cumulative attention ledgers.

function isUnboundedBudget(value) {
  return value === null || value === Infinity;
}

export function verifyAttentionLedger(ledger) {
  if (!ledger || ledger.protocol !== "ĀML Attention Ledger") throw new Error("Invalid ĀML attention ledger.");

  const validFiniteBudget = typeof ledger.initial_budget === "number" && Number.isFinite(ledger.initial_budget) && ledger.initial_budget >= 0;
  if (!validFiniteBudget && !isUnboundedBudget(ledger.initial_budget)) {
    return {
      verified: false,
      entries: Array.isArray(ledger.entries) ? ledger.entries.length : 0,
      calculated_consumed: 0,
      calculated_remaining: ledger.initial_budget,
      totals_valid: false,
      checks: [],
      reason: "invalid initial attention budget"
    };
  }
  if (!Array.isArray(ledger.entries)) {
    return {
      verified: false,
      entries: 0,
      calculated_consumed: 0,
      calculated_remaining: ledger.initial_budget,
      totals_valid: false,
      checks: [],
      reason: "attention ledger entries must be an array"
    };
  }

  const unbounded = isUnboundedBudget(ledger.initial_budget);
  let consumed = 0;
  let remaining = ledger.initial_budget;
  const checks = [];

  for (let i = 0; i < ledger.entries.length; i++) {
    const entry = ledger.entries[i];
    const sequenceValid = entry.sequence === i;
    const beforeValid = Object.is(entry.budget_before, remaining);
    const requestedValid = typeof entry.amount_requested === "number" && Number.isFinite(entry.amount_requested) && entry.amount_requested >= 0;
    const allowedExpected = requestedValid && (unbounded || entry.amount_requested <= remaining);
    const allowedValid = entry.allowed === allowedExpected;
    const expectedConsumed = allowedExpected ? entry.amount_requested : 0;
    const consumedValid = requestedValid && entry.amount_consumed === expectedConsumed;
    const expectedAfter = unbounded
      ? ledger.initial_budget
      : Math.max(0, remaining - expectedConsumed);
    const afterValid = Object.is(entry.budget_after, expectedAfter);

    if (allowedExpected) consumed += expectedConsumed;
    remaining = expectedAfter;

    checks.push({
      sequence: i,
      sequence_valid: sequenceValid,
      amount_requested_valid: requestedValid,
      allowed_valid: allowedValid,
      budget_before_valid: beforeValid,
      amount_consumed_valid: consumedValid,
      budget_after_valid: afterValid
    });
  }

  const totalsValid = ledger.consumed === consumed && Object.is(ledger.remaining, remaining);
  const entriesValid = checks.every(check =>
    check.sequence_valid &&
    check.amount_requested_valid &&
    check.allowed_valid &&
    check.budget_before_valid &&
    check.amount_consumed_valid &&
    check.budget_after_valid
  );

  return {
    verified: entriesValid && totalsValid,
    entries: ledger.entries.length,
    calculated_consumed: consumed,
    calculated_remaining: remaining,
    totals_valid: totalsValid,
    checks
  };
}

export function attentionLedgerSummary(ledger) {
  const verification = verifyAttentionLedger(ledger);
  return {
    protocol: "ĀML Attention Ledger Summary",
    version: "1.0",
    session_id: ledger.session_id || null,
    initial_budget: ledger.initial_budget,
    consumed: ledger.consumed,
    remaining: ledger.remaining,
    requests: ledger.entries.length,
    allowed_requests: ledger.entries.filter(entry => entry.allowed).length,
    denied_requests: ledger.entries.filter(entry => !entry.allowed).length,
    verified: verification.verified
  };
}
