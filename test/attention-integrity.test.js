import test from "node:test";
import assert from "node:assert/strict";

import {
  createAttentionLedger,
  consumeAttention,
  verifyAttentionLedger
} from "../index.js";

test("JSON-safe null sentinel preserves unbounded attention semantics", () => {
  const ledger = createAttentionLedger(null, { session_id: "json-safe" });
  const first = consumeAttention(ledger, 3);
  const second = consumeAttention(ledger, 1000);

  assert.equal(first.allowed, true);
  assert.equal(second.allowed, true);
  assert.equal(ledger.initial_budget, null);
  assert.equal(ledger.remaining, null);
  assert.equal(ledger.consumed, 1003);

  const roundTripped = JSON.parse(JSON.stringify(ledger));
  assert.equal(verifyAttentionLedger(roundTripped).verified, true);
});

test("legacy in-memory Infinity budget remains supported", () => {
  const ledger = createAttentionLedger();
  consumeAttention(ledger, 4);

  assert.equal(ledger.initial_budget, Infinity);
  assert.equal(ledger.remaining, Infinity);
  assert.equal(verifyAttentionLedger(ledger).verified, true);
});

test("attention verification rejects an allowed flag inconsistent with a finite budget", () => {
  const ledger = createAttentionLedger(2);
  consumeAttention(ledger, 3);
  assert.equal(verifyAttentionLedger(ledger).verified, true);

  ledger.entries[0].allowed = true;
  ledger.entries[0].amount_consumed = 0;
  assert.equal(verifyAttentionLedger(ledger).verified, false);
});
