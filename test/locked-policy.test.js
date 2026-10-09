import test from "node:test";
import assert from "node:assert/strict";
import { createLockedHttpPolicy } from "../server/lockedPolicy.js";

test("locked HTTP policy owns controls and rejects request overrides", async () => {
  const source = { consent_granted: false };
  const policy = createLockedHttpPolicy({ profile: "human_first", context: source, max_batch_items: 4 });
  source.consent_granted = true;
  const controls = await policy.select({ intent: { transmission: "example" } }, {});
  assert.equal(controls.mode, "enforce");
  assert.equal(controls.failure_mode, "closed");
  assert.equal(controls.context.consent_granted, false);
  assert.equal(controls.max_items, 4);
  controls.context.consent_granted = true;
  assert.equal((await policy.select({}, {})).context.consent_granted, false);

  for (const key of ["profile", "mode", "failure_mode", "context", "timestamp", "max_items"]) {
    await assert.rejects(policy.select({ [key]: undefined }, {}), {
      message: "policy_override_forbidden", statusCode: 403
    });
  }
});

test("trusted context resolver fails closed and never falls back to request context", async () => {
  const policy = createLockedHttpPolicy({
    resolve_context: async () => ({ privacy_consent: true })
  });
  assert.deepEqual((await policy.select({}, {})).context, { privacy_consent: true });
  await assert.rejects(policy.select({ context: { privacy_consent: true } }, {}), {
    message: "policy_override_forbidden", statusCode: 403
  });

  const unavailable = createLockedHttpPolicy({ resolve_context: async () => { throw new Error("private detail"); } });
  await assert.rejects(unavailable.select({}, {}), {
    message: "trusted_context_unavailable", statusCode: 503
  });
});

test("locked policy bounds stalled context lookup and signals cancellation", async () => {
  let signal;
  const policy = createLockedHttpPolicy({
    resolve_context_timeout_ms: 10,
    resolve_context: (_req, controls) => {
      signal = controls.signal;
      return new Promise(() => {});
    }
  });
  await assert.rejects(policy.select({}, {}), {
    message: "trusted_context_unavailable", statusCode: 503
  });
  assert.equal(signal.aborted, true);
});

test("invalid server policy configuration is rejected at startup", () => {
  assert.throws(() => createLockedHttpPolicy({ profile: "unknown" }), /Unknown ĀML policy profile/);
  assert.throws(() => createLockedHttpPolicy({ mode: "observe" }), /locked_policy.mode/);
  assert.throws(() => createLockedHttpPolicy({ failure_mode: "maybe" }), /locked_policy.failure_mode/);
  assert.throws(() => createLockedHttpPolicy({ context: {}, resolve_context: () => ({}) }), /mutually exclusive/);
  assert.throws(() => createLockedHttpPolicy({ max_batch_items: 0 }), /positive safe integer/);
  assert.throws(() => createLockedHttpPolicy({ resolve_context_timeout_ms: 0 }), /resolve_context_timeout_ms/);
  assert.throws(() => createLockedHttpPolicy({ typo: true }), /unknown locked_policy option/);
});
