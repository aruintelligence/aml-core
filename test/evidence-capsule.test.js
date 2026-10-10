import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import { canonicalJSONStringify } from "../protocol/canonicalJson.js";
import { executeAccountableIntent, signExecutionReceipt } from "../compiler/accountablePipeline.js";
import { createEvidenceCapsule, verifyEvidenceCapsule } from "../runtime/evidenceCapsule.js";

const intent = {
  transmission: "capsule-test",
  nodes: [{ type: "message", identifier: "ClearHelp", properties: {
    purpose: "Explain the next action", user_effect: "Reduce uncertainty",
    attention_cost: 1, restoration_value: 3, collects_personal_data: false,
    consent_required: false, contrast_safe: true, cognitive_load: 1
  } }]
};
const receipt = () => executeAccountableIntent(intent, { timestamp: "2026-10-10T00:00:00.000Z", profile: "human_first" });

test("capsule survives JSON round trip and gives deterministic dual digests", () => {
  const first = createEvidenceCapsule(receipt());
  const second = createEvidenceCapsule(receipt());
  assert.deepEqual(first.digests, second.digests);
  assert.equal(verifyEvidenceCapsule(JSON.parse(JSON.stringify(first))).verified, true);
  assert.equal(first.summary.allowed, 1);
});

test("capsule detects receipt, summary, digest and contract mutations", () => {
  const original = createEvidenceCapsule(receipt());
  for (const mutate of [
    c => { c.receipt.intent.transmission = "altered"; },
    c => { c.summary.allowed = 9; },
    c => { c.digests.sha512 = "0".repeat(128); },
    c => { c.claim_boundary = "independently certified"; },
    c => { c.extra = "unsupported extension"; }
  ]) {
    const changed = structuredClone(original);
    mutate(changed);
    assert.equal(verifyEvidenceCapsule(changed).verified, false);
  }
});

test("capsule rejects forged summaries even after outer digests are recomputed", () => {
  const capsule = createEvidenceCapsule(receipt());
  capsule.summary.allowed = 99;
  const { digests, ...payload } = capsule;
  // An attacker may freely calculate fresh unsalted digests. They cannot turn
  // the receipt's bound decision into the new summary by doing so.
  const bytes = canonicalJSONStringify(payload);
  capsule.digests = Object.fromEntries(["sha256", "sha512"].map(name => [name, crypto.createHash(name).update(bytes).digest("hex")]));
  assert.equal(verifyEvidenceCapsule(capsule).reason, "summary_mismatch");
});

test("signed receipt retains valid signature inside capsule", () => {
  const { privateKey } = crypto.generateKeyPairSync("ed25519");
  const signed = signExecutionReceipt(receipt(), privateKey.export({ type: "pkcs8", format: "pem" }), { signer: "test", timestamp: "2026-10-10T00:00:00.000Z" });
  const capsule = createEvidenceCapsule(signed);
  assert.equal(verifyEvidenceCapsule(capsule).verified, true);
  assert.equal(capsule.summary.signed, true);
  signed.signature.signer = "forged";
  assert.throws(() => createEvidenceCapsule(signed), /AML_CAPSULE_INVALID_SIGNATURE/);
});

test("unsupported values fail closed", () => {
  const capsule = createEvidenceCapsule(receipt());
  capsule.summary.extra = undefined;
  assert.equal(verifyEvidenceCapsule(capsule).verified, false);
});
