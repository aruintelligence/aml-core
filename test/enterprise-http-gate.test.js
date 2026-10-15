import test from "node:test";
import assert from "node:assert/strict";
import { createHash, generateKeyPairSync, randomBytes } from "node:crypto";
import fs from "node:fs";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { applyVerifiedDecision, evaluateAndGate } from "../pilots/enterprise-http-gate/host-gate.mjs";
import { executeAccountableIntent, signExecutionReceipt } from "../compiler/accountablePipeline.js";

const root = fileURLToPath(new URL("..", import.meta.url));
const load = (name) => JSON.parse(fs.readFileSync(new URL(`../pilots/enterprise-30min/${name}`, import.meta.url), "utf8"));

test("enterprise HTTP pilot gates a signed local service across thirteen outcomes", () => {
  const run = spawnSync(process.execPath, ["pilots/enterprise-http-gate/run.mjs"], {
    cwd: root, encoding: "utf8"
  });
  assert.equal(run.status, 0, run.stderr);
  const report = JSON.parse(run.stdout);
  assert.equal(report.protocol, "aml-enterprise-http-gate-pilot/1");
  assert.equal(report.passed, true);
  assert.match(report.source_revision, /^[0-9a-f]{40}$/);
  assert.equal(report.render_callback_entries, 2);
  assert.deepEqual(report.cases.map(({ id, status }) => [id, status]), [
    ["verified_allow", "rendered"],
    ["consent_suppression", "blocked"],
    ["changed_receipt", "blocked"],
    ["unsigned_receipt", "blocked"],
    ["untrusted_signer", "blocked"],
    ["receipt_replay_other_nonce", "blocked"],
    ["valid_receipt_for_other_intent", "blocked"],
    ["changed_decision", "blocked"],
    ["shadow_response", "blocked"],
    ["caller_policy_override", "blocked"],
    ["evaluation_error", "blocked"],
    ["transport_failure", "blocked"],
    ["render_callback_uncertain", "unknown"]
  ]);
  assert.equal(report.cases.filter(item => item.render_attempted).length, 2);
  assert.equal(run.stdout.includes('"receipt":'), false);
});

test("a valid receipt for a different trusted context cannot reach the host renderer", async () => {
  const intent = load("intent-sensitive.json");
  const actualContext = load("context-allowed.json");
  const expectedContext = load("context-denied.json");
  const requestNonce = randomBytes(32).toString("hex");
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const receipt = executeAccountableIntent(intent, { profile: "human_first",
    context: actualContext, request_nonce: requestNonce,
    timestamp: "2030-01-01T00:00:00.000Z", stream_id: "test-trusted-context" });
  const signed = signExecutionReceipt(receipt,
    privateKey.export({ type: "pkcs8", format: "pem" }), { signer: "test" });
  const trustedReceiptFingerprints = [createHash("sha256")
    .update(publicKey.export({ type: "spki", format: "der" })).digest("hex")];
  assert.equal(receipt.selected_render.suppressed, 0);
  let calls = 0;
  const result = await applyVerifiedDecision({ httpStatus: 200, intent, profile: "human_first",
    context: expectedContext, requestNonce, trustedReceiptFingerprints,
    render: () => { calls += 1; },
    body: { protocol: "aml-http-deployment-evaluation/1", policy_source: "server",
      mode: "enforce", failure_mode: "closed", evaluation_error: null,
      aml_allowed: true, effective_allowed: true, would_suppress: false, receipt: signed } });
  assert.deepEqual([result.status, result.reason, calls], ["blocked", "receipt_binding_mismatch", 0]);
});

test("a host without a pinned signer fails before sending a request", async () => {
  let requests = 0;
  let renders = 0;
  const result = await evaluateAndGate({ url: "http://127.0.0.1/", token: "local",
    intent: load("intent-allowed.json"), profile: "human_first", context: {},
    trustedReceiptFingerprints: [], render: () => { renders += 1; },
    fetchImpl: async () => { requests += 1; throw new Error("should not send"); } });
  assert.deepEqual([result.status, result.reason, requests, renders],
    ["blocked", "trust_anchor_unavailable", 0, 0]);
});
