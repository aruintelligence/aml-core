import test from "node:test";
import assert from "node:assert/strict";
import {
  createTransparencyLog,
  appendTransparencyEntry,
  verifyTransparencyLog
} from "../index.js";

test("valid transparency log still verifies", () => {
  let log = createTransparencyLog();
  log = appendTransparencyEntry(log, { action: "allow" });
  const result = verifyTransparencyLog(log);
  assert.equal(result.valid, true);
  assert.equal(result.size, 1);
});

test("transparency verifier rejects object entries instead of accepting an empty loop", () => {
  const malformed = { type: "aml-transparency-log/1", entries: {}, head: null };
  const result = verifyTransparencyLog(malformed);
  assert.deepEqual(result, { valid: false, reason: "invalid_entries" });
});

test("transparency verifier fails closed on malformed entries and hashes", () => {
  const base = createTransparencyLog();
  const candidates = [
    { ...base, entries: [null] },
    { ...base, head: "bad" },
    { ...base, entries: [{ index: 0, previous_hash: null, payload_hash: "bad", timestamp: null, entry_hash: "bad" }] }
  ];

  for (const candidate of candidates) {
    assert.doesNotThrow(() => verifyTransparencyLog(candidate));
    assert.equal(verifyTransparencyLog(candidate).valid, false);
  }
});

test("transparency append rejects malformed log state before mutation", () => {
  assert.throws(
    () => appendTransparencyEntry({ type: "aml-transparency-log/1", entries: {}, head: null }, { action: "allow" }),
    /Invalid transparency log entries/
  );
});
