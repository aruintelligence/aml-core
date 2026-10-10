import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import { createEvidenceMigration, verifyEvidenceMigration } from "../runtime/evidenceMigration.js";
import { createEvidenceArchive } from "../runtime/evidenceArchive.js";
import { createEvidenceCapsule } from "../runtime/evidenceCapsule.js";
import { createEvidenceRenewal, attestEvidenceRenewal } from "../runtime/evidenceRenewal.js";
import { signExecutionReceipt } from "../compiler/accountablePipeline.js";
import { canonicalJSONStringify } from "../protocol/canonicalJson.js";

const source = JSON.parse(fs.readFileSync(new URL("../independent/vectors/archive-v1/archive.json", import.meta.url), "utf8"));
const trust = JSON.parse(fs.readFileSync(new URL("../independent/vectors/archive-v1/trusted-policy.json", import.meta.url), "utf8"));
const hash = (algorithm, bytes) => crypto.createHash(algorithm).update(bytes).digest("hex");
const rehash = migration => {
  const { root_sha3_512, root_sha512, ...payload } = migration;
  const bytes = canonicalJSONStringify(payload);
  migration.root_sha3_512 = hash("sha3-512", bytes);
  migration.root_sha512 = hash("sha512", bytes);
};

test("v2 handoff preserves canonical v1 bytes and verifies external trust", () => {
  const migration = createEvidenceMigration(source, trust);
  assert.equal(Buffer.from(migration.source_archive_base64, "base64").toString("utf8"), canonicalJSONStringify(source));
  const result = verifyEvidenceMigration(JSON.parse(JSON.stringify(migration)), trust);
  assert.equal(result.verified, true);
  assert.equal(result.component_equivalent, true);
  assert.equal(result.freshness_bound, true);
  assert.equal(result.policy_hint_trusted, false);
  assert.equal(result.source_archive_root_sha3_512, source.root_sha3_512);
});

test("handoff cannot use its policy hint as trust or hide source rollback", () => {
  const migration = createEvidenceMigration(source, trust);
  assert.equal(verifyEvidenceMigration(migration).reason, "external_trust_required");
  assert.equal(verifyEvidenceMigration(migration, { threshold: 1, trusted_fingerprints: ["f".repeat(64)] }).verified, false);
  const fork = { ...trust, accepted_head: { sequence: 2, root_sha3_512: "a".repeat(128) } };
  assert.equal(verifyEvidenceMigration(migration, fork).reason, "source_renewal_accepted_head_missing_or_forked");
});

test("rehashing v2 cannot conceal changed target component or v1 summary", () => {
  const migration = createEvidenceMigration(source, trust);
  const replaced = structuredClone(migration);
  const differentHint = Buffer.from(canonicalJSONStringify({ note: "replacement" }));
  replaced.policy_hint_base64 = differentHint.toString("base64");
  replaced.manifest.policy_hint_sha3_512 = hash("sha3-512", differentHint);
  replaced.manifest.policy_hint_sha512 = hash("sha512", differentHint);
  rehash(replaced);
  assert.equal(verifyEvidenceMigration(replaced, trust).reason, "component_equivalence_mismatch");

  const rewritten = structuredClone(migration);
  const alteredSource = structuredClone(source);
  alteredSource.summary.renewal_count = 99;
  const { root_sha3_512, ...sourcePayload } = alteredSource;
  alteredSource.root_sha3_512 = hash("sha3-512", canonicalJSONStringify(sourcePayload));
  const sourceBytes = Buffer.from(canonicalJSONStringify(alteredSource));
  rewritten.source_archive_base64 = sourceBytes.toString("base64");
  rewritten.manifest.source_archive_sha3_512 = hash("sha3-512", sourceBytes);
  rewritten.manifest.source_archive_sha512 = hash("sha512", sourceBytes);
  rehash(rewritten);
  assert.equal(verifyEvidenceMigration(rewritten, trust).reason, "source_summary_mismatch");
});

test("missing or noncanonical source cannot be recovered", () => {
  const migration = createEvidenceMigration(source, trust);
  const missing = structuredClone(migration);
  delete missing.source_archive_base64;
  assert.equal(verifyEvidenceMigration(missing, trust).verified, false);
  const changed = structuredClone(migration);
  changed.source_archive_base64 = Buffer.from(JSON.stringify(source, null, 2)).toString("base64");
  changed.manifest.source_archive_sha3_512 = hash("sha3-512", Buffer.from(changed.source_archive_base64, "base64"));
  changed.manifest.source_archive_sha512 = hash("sha512", Buffer.from(changed.source_archive_base64, "base64"));
  rehash(changed);
  assert.equal(verifyEvidenceMigration(changed, trust).reason, "malformed_migration");
});

test("signed source requires a separately trusted receipt key", () => {
  const { privateKey } = crypto.generateKeyPairSync("ed25519");
  const pem = privateKey.export({ type: "pkcs8", format: "pem" });
  const originalCapsule = JSON.parse(Buffer.from(source.capsule_base64, "base64").toString("utf8"));
  const signedReceipt = signExecutionReceipt(originalCapsule.receipt, pem, { signer: "synthetic", timestamp: "2026-10-10T03:00:00.000Z" });
  const capsule = createEvidenceCapsule(signedReceipt);
  const record = createEvidenceRenewal(capsule, { sequence: 1, created_at: "2026-10-10T04:00:00.000Z" });
  const witness = attestEvidenceRenewal(record, pem, { signer: "synthetic", signed_at: "2026-10-10T04:00:00.000Z" });
  const policy = { threshold: 1, trusted_fingerprints: [witness.public_key_fingerprint_sha256] };
  const archive = createEvidenceArchive(capsule, [{ record, witnesses: [witness] }], policy);
  assert.throws(() => createEvidenceMigration(archive, policy), /EXTERNAL_RECEIPT_TRUST_REQUIRED/);
  const trusted = { ...policy, trusted_receipt_fingerprints: [signedReceipt.signature.public_key_sha256] };
  const migration = createEvidenceMigration(archive, trusted);
  assert.equal(verifyEvidenceMigration(migration, trusted).verified, true);
  assert.equal(verifyEvidenceMigration(migration, policy).reason, "external_receipt_trust_required");
  assert.equal(verifyEvidenceMigration(migration, { ...trusted,
    revoked_receipt_fingerprints: trusted.trusted_receipt_fingerprints }).reason, "receipt_signer_revoked");
});
