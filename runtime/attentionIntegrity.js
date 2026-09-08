// runtime/attentionIntegrity.js
// ĀML v1.3 — consistency verification for cumulative attention ledgers.

export function verifyAttentionLedger(ledger) {
  if (!ledger || ledger.protocol !== "ĀML Attention Ledger") throw new Error("Invalid ĀML attention ledger.");

  let consumed = 0;
  let remaining = ledger.initial_budget;
  const checks = [];

  for (let i = 0; i < ledger.entries.length; i++) {
    const entry = ledger.entries[i];
    const sequenceValid = entry.sequence === i;
    const beforeValid = Object.is(entry.budget_before, remaining);
    const expectedConsumed = entry.allowed ? entry.amount_requested : 0;
    const consumedValid = entry.amount_consumed === expectedConsumed;
    const expectedAfter = Number.isFinite(ledger.initial_budget)
      ? Math.max(0, remaining - expectedConsumed)
      : Infinity;
    const afterValid = Object.is(entry.budget_after, expectedAfter);

    if (entry.allowed) consumed += expectedConsumed;
    remaining = expectedAfter;

    checks.push({
      sequence: i,
      sequence_valid: sequenceValid,
      budget_before_valid: beforeValid,
      amount_consumed_valid: consumedValid,
      budget_after_valid: afterValid
    });
  }

  const totalsValid = ledger.consumed === consumed && Object.is(ledger.remaining, remaining);
  const entriesValid = checks.every(check =>
    check.sequence_valid && check.budget_before_valid && check.amount_consumed_valid && check.budget_after_valid
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
