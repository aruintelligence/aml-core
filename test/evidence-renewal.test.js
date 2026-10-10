import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import { executeAccountableIntent } from "../compiler/accountablePipeline.js";
import { createEvidenceCapsule } from "../runtime/evidenceCapsule.js";
import { createEvidenceRenewal, attestEvidenceRenewal, verifyEvidenceRenewalChain } from "../runtime/evidenceRenewal.js";

const intent = { transmission: "renewal-test", nodes: [{ type: "message", identifier: "Help", properties: {
  purpose: "Explain the next step", user_effect: "Reduce uncertainty", attention_cost: 1,
  restoration_value: 3, collects_personal_data: false, consent_required: false,
  contrast_safe: true, cognitive_load: 1
} }] };
const capsule = createEvidenceCapsule(executeAccountableIntent(intent, { timestamp: "2026-10-10T00:00:00.000Z", profile: "human_first" }));
const keys = Array.from({ length: 3 }, () => crypto.generateKeyPairSync("ed25519").privateKey.export({ type: "pkcs8", format: "pem" }));
const witness = (record, index) => attestEvidenceRenewal(record, keys[index], { signer: `synthetic-${index}`, signed_at: "2026-10-10T01:00:00.000Z" });
const fingerprints = keys.map(key => witness(createEvidenceRenewal(capsule, { sequence: 1, created_at: "2026-10-10T00:30:00.000Z" }), keys.indexOf(key)).public_key_fingerprint_sha256);
const first = createEvidenceRenewal(capsule, { sequence: 1, created_at: "2026-10-10T00:30:00.000Z" });
const second = createEvidenceRenewal(capsule, { sequence: 2, previous_root_sha3_512: first.root_sha3_512, created_at: "2026-10-10T02:00:00.000Z" });
const chain = [
  { record: first, witnesses: [witness(first, 0), witness(first, 1)] },
  { record: second, witnesses: [witness(second, 1), witness(second, 2)] }
];
const policy = { threshold: 2, trusted_fingerprints: fingerprints,
  trusted_fingerprints_by_sequence: { 1: fingerprints.slice(0, 2), 2: fingerprints.slice(1) },
  accepted_head: { sequence: 1, root_sha3_512: first.root_sha3_512 } };

test("renewal chain accepts explicit two-key rotation and remembered head", () => {
  const result = verifyEvidenceRenewalChain(capsule, chain, policy);
  assert.equal(result.verified, true);
  assert.equal(result.freshness_bound, true);
  assert.equal(result.sequence, 2);
  assert.equal(result.head_root_sha3_512, second.root_sha3_512);
});

test("rejects missing trust, quorum, duplicate key and revoked key", () => {
  assert.equal(verifyEvidenceRenewalChain(capsule, chain, { threshold: 2, trusted_fingerprints: [] }).verified, false);
  const duplicate = structuredClone(chain);
  duplicate[0].witnesses[1] = duplicate[0].witnesses[0];
  assert.equal(verifyEvidenceRenewalChain(capsule, duplicate, policy).reason, "quorum_not_met");
  assert.equal(verifyEvidenceRenewalChain(capsule, chain, { ...policy, revoked_fingerprints: [fingerprints[1]] }).verified, false);
  assert.equal(verifyEvidenceRenewalChain(capsule, chain, { ...policy, trusted_fingerprints_by_sequence: { 1: fingerprints.slice(0, 2), 2: fingerprints.slice(0, 2) } }).verified, false);
  assert.equal(verifyEvidenceRenewalChain(capsule, chain, { ...policy, trusted_fingerprints_by_sequence: { 1: fingerprints.slice(0, 2) } }).reason, "invalid_trust_policy");
});

test("rejects broken succession, rollback, fork and capsule replacement", () => {
  const skip = structuredClone(chain);
  skip[1].record.sequence = 3;
  assert.equal(verifyEvidenceRenewalChain(capsule, skip, policy).verified, false);
  const fork = { ...policy, accepted_head: { sequence: 1, root_sha3_512: "a".repeat(128) } };
  assert.equal(verifyEvidenceRenewalChain(capsule, chain, fork).reason, "accepted_head_missing_or_forked");
  assert.equal(verifyEvidenceRenewalChain(capsule, chain.slice(0, 1), { ...policy, accepted_head: { sequence: 2, root_sha3_512: second.root_sha3_512 } }).verified, false);
  const other = structuredClone(capsule);
  other.summary.allowed = 99;
  assert.equal(verifyEvidenceRenewalChain(other, chain, policy).reason, "invalid_capsule");
});

test("rejects changed attribution, record root, unsupported fields and malformed values", () => {
  const altered = structuredClone(chain);
  altered[0].witnesses[0].signer = "different signer";
  assert.equal(verifyEvidenceRenewalChain(capsule, altered, policy).reason, "quorum_not_met");
  const forged = structuredClone(chain);
  forged[1].record.capsule_sha3_512 = "f".repeat(128);
  assert.equal(verifyEvidenceRenewalChain(capsule, forged, policy).verified, false);
  const extra = structuredClone(chain);
  extra[0].record.claimed_future_algorithm = "magic";
  assert.equal(verifyEvidenceRenewalChain(capsule, extra, policy).verified, false);
  const malformed = structuredClone(chain);
  malformed[0].record.created_at = undefined;
  assert.equal(verifyEvidenceRenewalChain(capsule, malformed, policy).verified, false);
});

test("constructors reject invalid predecessors and keys", () => {
  assert.throws(() => createEvidenceRenewal(capsule, { sequence: 2 }), /INVALID_PREDECESSOR/);
  const rsa = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 }).privateKey.export({ type: "pkcs8", format: "pem" });
  assert.throws(() => attestEvidenceRenewal(first, rsa), /UNSUPPORTED_KEY/);
});
