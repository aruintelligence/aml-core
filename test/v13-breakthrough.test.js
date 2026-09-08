import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";

import { policyMatrix } from "../compiler/policyMatrix.js";
import { semanticRiskDiff } from "../compiler/semanticRisk.js";
import { createAuditStream, appendAuditEvent } from "../runtime/auditStream.js";
import { signAuditCheckpoint, verifyAuditCheckpoint } from "../runtime/auditAttestation.js";
import { createAttentionLedger, consumeAttention } from "../runtime/attentionLedger.js";
import { verifyAttentionLedger } from "../runtime/attentionIntegrity.js";
import { auditAccessibilityNode } from "../runtime/accessibilityAudit.js";

test("policy matrix compares several policy regimes over identical source", () => {
  const source = fs.readFileSync("examples/simple.aml", "utf8");
  const matrix = policyMatrix(source, ["restorative_v1", "attention_conservative_v1", "calm_default"]);
  assert.equal(matrix.protocol, "ĀML Policy Matrix");
  assert.equal(matrix.targets.length, 3);
  assert.ok(matrix.nodes >= 1);
  assert.equal(typeof matrix.disagreements, "number");
});

test("semantic risk diff elevates meaning-bearing policy changes", () => {
  const left = `transmission "risk" {\n  engram Card {\n    purpose: "inform"\n    attention_cost: 1\n    restoration_value: 5\n  }\n}`;
  const right = `transmission "risk" {\n  engram Card {\n    purpose: "extract"\n    attention_cost: 5\n    restoration_value: 1\n  }\n}`;
  const result = semanticRiskDiff(left, right);
  assert.ok(result.changed.length >= 1);
  assert.ok(result.summary.high_risk >= 1 || result.summary.medium_risk >= 1);
});

test("audit checkpoint binds a valid hash-chain head and detects later mutation", () => {
  const stream = createAuditStream({ stream_id: "test-stream", timestamp: "2026-01-01T00:00:00.000Z" });
  appendAuditEvent(stream, { event_type: "render", payload: { allowed: true } }, { timestamp: "2026-01-01T00:00:01.000Z" });
  const { privateKey } = crypto.generateKeyPairSync("ed25519");
  const privatePem = privateKey.export({ type: "pkcs8", format: "pem" });
  const signed = signAuditCheckpoint(stream, privatePem, { signer: "test", timestamp: "2026-01-01T00:00:02.000Z" });
  assert.equal(verifyAuditCheckpoint(stream, signed).verified, true);
  stream.entries[0].payload.allowed = false;
  assert.equal(verifyAuditCheckpoint(stream, signed).verified, false);
});

test("attention ledger verification detects accounting tampering", () => {
  const ledger = createAttentionLedger(5, { session_id: "session-1" });
  consumeAttention(ledger, 2, { component: "one" });
  consumeAttention(ledger, 4, { component: "two" });
  assert.equal(verifyAttentionLedger(ledger).verified, true);
  ledger.entries[0].amount_consumed = 1;
  assert.equal(verifyAttentionLedger(ledger).verified, false);
});

test("accessibility audit catches missing keyboard and text alternatives", () => {
  const result = auditAccessibilityNode({
    identifier: "hero-action",
    properties: {
      interactive: true,
      visual_only: true,
      motion_required: true,
      reduced_motion_alternative: false,
      contrast_safe: false,
      cognitive_load: 8
    }
  }, {
    prefers_reduced_motion: true,
    high_contrast_required: true,
    max_cognitive_load: 4
  });
  assert.equal(result.passed, false);
  assert.ok(result.checks.some(check => check.id === "AML_A11Y_KEYBOARD" && !check.ok));
  assert.ok(result.checks.some(check => check.id === "AML_A11Y_TEXT_ALT" && !check.ok));
});
