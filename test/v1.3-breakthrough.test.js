import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";

import {
  semanticDiff,
  policyDiff,
  compileSource,
  signPolicyPack,
  verifySignedPolicyPack,
  createAuditStream,
  appendAuditEvent,
  verifyAuditStream,
  createAttentionLedger,
  consumeAttention,
  accountRenderDecisions,
  attentionContext,
  listPolicyProfiles
} from "../index.js";

const timestamp = "2031-01-01T00:00:00.000Z";

function source(restoration = 5.5, extra = "") {
  return `transmission "v13" {\n  engram "nodeA" {\n    purpose: "Demonstrate v1.3 accountability."\n    attention_cost: 5\n    restoration_value: ${restoration}\n${extra}  }\n}\n`;
}

test("semantic diff detects meaning changes rather than only text changes", () => {
  const diff = semanticDiff(source(5.5), source(8), { timestamp });
  assert.equal(diff.protocol, "ĀML Semantic Diff");
  assert.equal(diff.summary.changed, 1);
  assert.equal(diff.changed[0].meaning_changes.restoration_value.before, 5.5);
  assert.equal(diff.changed[0].meaning_changes.restoration_value.after, 8);
});

test("policy diff exposes a changed render decision over identical source", () => {
  const diff = policyDiff(source(5.5), "restorative_v1", "attention_conservative_v1", { timestamp });
  assert.equal(diff.protocol, "ĀML Policy Diff");
  assert.equal(diff.changed_decisions, 1);
  assert.equal(diff.changes[0].left.render_allowed, true);
  assert.equal(diff.changes[0].right.render_allowed, false);
});

test("signed policy packs verify and mutation is detected", () => {
  const { privateKey } = crypto.generateKeyPairSync("ed25519");
  const privatePem = privateKey.export({ type: "pkcs8", format: "pem" });
  const signed = signPolicyPack({
    id: "test_pack",
    issuer: "ĀML test suite",
    policies: ["restorative_v1", "consent_guard_v1"]
  }, privatePem, { timestamp });

  assert.equal(verifySignedPolicyPack(signed).verified, true);
  const mutated = structuredClone(signed);
  mutated.description = "tampered";
  assert.equal(verifySignedPolicyPack(mutated).verified, false);
});

test("runtime audit stream is hash chained and detects mutation", () => {
  const stream = createAuditStream({ stream_id: "session-1", timestamp });
  appendAuditEvent(stream, { event_type: "render", payload: { allowed: true } }, { timestamp });
  appendAuditEvent(stream, { event_type: "attention", payload: { consumed: 2 } }, { timestamp });
  assert.equal(verifyAuditStream(stream).verified, true);

  stream.entries[0].payload.allowed = false;
  assert.equal(verifyAuditStream(stream).verified, false);
});

test("cumulative attention ledger carries budget across decisions", () => {
  const ledger = createAttentionLedger(5, { session_id: "attention-test" });
  assert.equal(consumeAttention(ledger, 2).allowed, true);
  assert.equal(ledger.remaining, 3);
  assert.equal(consumeAttention(ledger, 4).allowed, false);
  assert.equal(ledger.remaining, 3);
  assert.equal(attentionContext(ledger).attention_budget_remaining, 3);
});

test("render decisions can be cumulatively accounted", () => {
  const ledger = createAttentionLedger(10);
  const decisions = compileSource(source(8), { timestamp }).renderDecisions;
  const entries = accountRenderDecisions(ledger, decisions);
  assert.equal(entries[0].allowed, true);
  assert.equal(ledger.consumed, 5);
  assert.equal(ledger.remaining, 5);
});

test("reduced-motion accessibility policy suppresses motion-required nodes without an alternative", () => {
  const motionSource = source(8, "    motion_required: required\n");
  const denied = compileSource(motionSource, {
    timestamp,
    policy: "reduced_motion_v1",
    context: { prefers_reduced_motion: true }
  });
  assert.equal(denied.renderDecisions[0].render_allowed, false);
});

test("reduced-motion alternative allows the same accessibility policy to pass", () => {
  const motionSource = source(8, "    motion_required: required\n    reduced_motion_alternative: true\n");
  const allowed = compileSource(motionSource, {
    timestamp,
    policy: "reduced_motion_v1",
    context: { prefers_reduced_motion: true }
  });
  assert.equal(allowed.renderDecisions[0].render_allowed, true);
});

test("accessibility-first and human-first profiles are discoverable", () => {
  const ids = listPolicyProfiles().map(item => item.id);
  assert.ok(ids.includes("accessibility_first"));
  assert.ok(ids.includes("human_first"));
});
