import test from "node:test";
import assert from "node:assert/strict";
import { createWireEnvelope, validateWireEnvelope, createReplayGuard, acceptWireEnvelope } from "../index.js";

test("wire envelope replay metadata is accepted once per session+nonce", () => {
  const envelope = createWireEnvelope({
    kind: "execution_receipt",
    payload: { id: "r1" },
    session_id: "s1",
    nonce: "n1",
    issued_at: "2026-01-01T00:00:00.000Z",
    expires_at: "2026-01-01T00:10:00.000Z"
  });

  assert.equal(validateWireEnvelope(envelope, { now: "2026-01-01T00:05:00.000Z" }).valid, true);

  const first = acceptWireEnvelope(createReplayGuard(), envelope, { now: "2026-01-01T00:05:00.000Z" });
  assert.equal(first.accepted, true);

  const second = acceptWireEnvelope(first.guard, envelope, { now: "2026-01-01T00:05:01.000Z" });
  assert.equal(second.accepted, false);
  assert.equal(second.reason, "replay");
});

test("expired wire envelope is rejected", () => {
  const envelope = createWireEnvelope({
    kind: "execution_receipt",
    payload: {},
    session_id: "s1",
    nonce: "n2",
    expires_at: "2026-01-01T00:10:00.000Z"
  });

  assert.equal(validateWireEnvelope(envelope, { now: "2026-01-01T00:10:00.000Z" }).reason, "expired");
  assert.equal(acceptWireEnvelope(createReplayGuard(), envelope, { now: "2026-01-01T00:10:00.000Z" }).reason, "expired");
});
