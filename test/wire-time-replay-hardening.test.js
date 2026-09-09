import test from "node:test";
import assert from "node:assert/strict";
import {
  createWireEnvelope,
  validateWireEnvelope,
  createReplayGuard,
  acceptWireEnvelope
} from "../index.js";

test("wire envelope constructor rejects malformed and inverted time windows", () => {
  assert.throws(
    () => createWireEnvelope({ kind: "intent", payload: {}, expires_at: "tomorow" }),
    /valid expires_at/
  );
  assert.throws(
    () => createWireEnvelope({
      kind: "intent",
      payload: {},
      issued_at: "2026-09-09T01:00:00.000Z",
      expires_at: "2026-09-09T00:00:00.000Z"
    }),
    /expires_at after issued_at/
  );
});

test("wire validation fails closed on malformed transported time fields", () => {
  const base = createWireEnvelope({ kind: "intent", payload: {} });
  assert.equal(validateWireEnvelope({ ...base, expires_at: "tomorow" }).reason, "invalid_expires_at");
  assert.equal(validateWireEnvelope({ ...base, issued_at: "yesterday-ish" }).reason, "invalid_issued_at");
  assert.equal(validateWireEnvelope(base, { now: "whenever" }).reason, "invalid_now");
});

test("wire validation enforces expiration after validated parsing", () => {
  const envelope = createWireEnvelope({
    kind: "intent",
    payload: {},
    issued_at: "2026-09-09T00:00:00.000Z",
    expires_at: "2026-09-09T01:00:00.000Z"
  });
  assert.equal(validateWireEnvelope(envelope, { now: "2026-09-09T00:59:59.000Z" }).valid, true);
  assert.equal(validateWireEnvelope(envelope, { now: "2026-09-09T01:00:00.000Z" }).reason, "expired");
});

test("replay guard refuses invalid protocol envelopes before nonce acceptance", () => {
  const result = acceptWireEnvelope(createReplayGuard(), {
    protocol: "attacker-wire/1",
    version: "1.0",
    kind: "intent",
    session_id: "session-1",
    nonce: "nonce-1",
    payload: {}
  });
  assert.equal(result.accepted, false);
  assert.equal(result.reason, "invalid_protocol");
});

test("replay guard rejects malformed expiry instead of treating it as immortal", () => {
  const envelope = {
    ...createWireEnvelope({ kind: "intent", payload: {}, session_id: "session-1", nonce: "nonce-1" }),
    expires_at: "never-ish"
  };
  const result = acceptWireEnvelope(createReplayGuard(), envelope, { now: "2026-09-09T00:00:00.000Z" });
  assert.equal(result.accepted, false);
  assert.equal(result.reason, "invalid_expires_at");
});

test("replay guard preserves normal one-time acceptance semantics", () => {
  const envelope = createWireEnvelope({
    kind: "intent",
    payload: { action: "render" },
    session_id: "session-1",
    nonce: "nonce-1",
    expires_at: "2026-09-09T02:00:00.000Z"
  });
  const first = acceptWireEnvelope(createReplayGuard(), envelope, { now: "2026-09-09T01:00:00.000Z" });
  assert.equal(first.accepted, true);
  const second = acceptWireEnvelope(first.guard, envelope, { now: "2026-09-09T01:00:01.000Z" });
  assert.equal(second.accepted, false);
  assert.equal(second.reason, "replay");
});
