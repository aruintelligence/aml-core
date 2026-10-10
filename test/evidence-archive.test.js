import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import { executeAccountableIntent } from "../compiler/accountablePipeline.js";
import { createEvidenceCapsule } from "../runtime/evidenceCapsule.js";
import { createEvidenceRenewal, attestEvidenceRenewal } from "../runtime/evidenceRenewal.js";
import { createEvidenceArchive, verifyEvidenceArchive } from "../runtime/evidenceArchive.js";
import { canonicalJSONStringify } from "../protocol/canonicalJson.js";

const intent = { transmission: "archive-test", nodes: [{ type: "message", identifier: "Help", properties: {
  purpose: "Explain the next step", user_effect: "Reduce uncertainty", attention_cost: 1,
  restoration_value: 3, collects_personal_data: false, consent_required: false,
  contrast_safe: true, cognitive_load: 1
} }] };
const capsule = createEvidenceCapsule(executeAccountableIntent(intent, { timestamp: "2026-10-10T00:00:00.000Z", profile: "human_first" }));
const record = createEvidenceRenewal(capsule, { sequence: 1, created_at: "2026-10-10T01:00:00.000Z" });
const privateKey = crypto.generateKeyPairSync("ed25519").privateKey.export({ type: "pkcs8", format: "pem" });
const witness = attestEvidenceRenewal(record, privateKey, { signer: "synthetic", signed_at: "2026-10-10T01:00:00.000Z" });
const entries = [{ record, witnesses: [witness] }];
const policy = { threshold: 1, trusted_fingerprints: [witness.public_key_fingerprint_sha256], accepted_head: { sequence: 1, root_sha3_512: record.root_sha3_512 } };
const rehash = archive => {
  const { root_sha3_512, ...payload } = archive;
  archive.root_sha3_512 = crypto.createHash("sha3-512").update(canonicalJSONStringify(payload)).digest("hex");
};

test("archive preserves canonical bytes and verifies with external trusted keys", () => {
  const archive = createEvidenceArchive(capsule, entries, policy);
  const restored = JSON.parse(JSON.stringify(archive));
  assert.equal(Buffer.from(restored.capsule_base64, "base64").toString("utf8"), canonicalJSONStringify(capsule));
  const result = verifyEvidenceArchive(restored, policy);
  assert.equal(result.verified, true);
  assert.equal(result.freshness_bound, true);
  assert.equal(result.policy_hint_trusted, false);
});

test("archive never treats its policy hint as authority", () => {
  const archive = createEvidenceArchive(capsule, entries, policy);
  assert.equal(verifyEvidenceArchive(archive).reason, "external_trust_required");
  assert.equal(verifyEvidenceArchive(archive, { threshold: 1, trusted_fingerprints: ["f".repeat(64)] }).verified, false);
});

test("missing, swapped, noncanonical, and rewritten components fail", () => {
  const original = createEvidenceArchive(capsule, entries, policy);
  const missing = structuredClone(original);
  delete missing.renewals_base64;
  assert.equal(verifyEvidenceArchive(missing, policy).verified, false);
  const swapped = structuredClone(original);
  swapped.renewals_base64 = original.capsule_base64;
  rehash(swapped);
  assert.equal(verifyEvidenceArchive(swapped, policy).verified, false);
  const noncanonical = structuredClone(original);
  noncanonical.policy_hint_base64 = Buffer.from(JSON.stringify(policy, null, 2)).toString("base64");
  noncanonical.manifest.policy_hint_sha3_512 = crypto.createHash("sha3-512").update(Buffer.from(noncanonical.policy_hint_base64, "base64")).digest("hex");
  rehash(noncanonical);
  assert.equal(verifyEvidenceArchive(noncanonical, policy).reason, "malformed_archive");
  const changedSummary = structuredClone(original);
  changedSummary.summary.renewal_count = 99;
  rehash(changedSummary);
  assert.equal(verifyEvidenceArchive(changedSummary, policy).reason, "summary_mismatch");
});

test("rehashed archive cannot substitute a capsule without trusted renewal signatures", () => {
  const archive = createEvidenceArchive(capsule, entries, policy);
  const other = structuredClone(capsule);
  other.summary.allowed = 99;
  archive.capsule_base64 = Buffer.from(canonicalJSONStringify(other)).toString("base64");
  archive.manifest.capsule_sha3_512 = crypto.createHash("sha3-512").update(Buffer.from(archive.capsule_base64, "base64")).digest("hex");
  rehash(archive);
  assert.equal(verifyEvidenceArchive(archive, policy).reason, "invalid_capsule");
});
