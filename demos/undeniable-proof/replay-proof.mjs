import assert from "node:assert/strict";
import fs from "node:fs";
import { executeAccountableIntent, verifyExecutionReceipt } from "../../index.js";

const intent = JSON.parse(fs.readFileSync(new URL("./intent.json", import.meta.url), "utf8"));
const options = {
  timestamp: "2026-09-08T06:15:00.000Z",
  stream_id: "aml-undeniable-proof-0001",
  profile: "calm_default",
  context: {
    session_id: "aml-undeniable-proof-session",
    attention_budget_initial: 10,
    consent_granted: false
  }
};

const first = executeAccountableIntent(intent, options);
const second = executeAccountableIntent(intent, options);

const firstVerification = verifyExecutionReceipt(first);
const secondVerification = verifyExecutionReceipt(second);

assert.equal(firstVerification.verified, true, "first receipt must verify");
assert.equal(secondVerification.verified, true, "second receipt must verify");
assert.equal(first.receipt_sha256, second.receipt_sha256, "replayed receipt hashes must match exactly");
assert.equal(first.decision_sha256, second.decision_sha256, "replayed decision hashes must match exactly");
assert.equal(first.output_sha256, second.output_sha256, "replayed output hashes must match exactly");
assert.deepEqual(first, second, "fixed-input replay must produce an identical receipt object");

const countdown = first.selected_render.decisions.find(item => item.identifier === "countdown_pressure");
const purchase = first.selected_render.decisions.find(item => item.identifier === "purchase_action");
assert.equal(countdown?.render_allowed, false, "countdown pressure must be suppressed");
assert.equal(purchase?.render_allowed, true, "ordinary purchase action must remain allowed");

console.log(JSON.stringify({
  proof: "PASS",
  receipt_sha256: first.receipt_sha256,
  decision_sha256: first.decision_sha256,
  output_sha256: first.output_sha256,
  suppressed: first.selected_render.suppressed,
  allowed: first.selected_render.allowed
}, null, 2));
