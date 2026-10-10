import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import { canonicalJSONStringify } from "../protocol/canonicalJson.js";
import { createEvidenceMigration, verifyEvidenceMigration } from "../runtime/evidenceMigration.js";
import { createEvidenceArchive } from "../runtime/evidenceArchive.js";
import { createEvidenceRenewal, attestEvidenceRenewal } from "../runtime/evidenceRenewal.js";
import { createEvidenceShards, recoverEvidenceShards } from "../runtime/evidenceShards.js";

const migration = JSON.parse(fs.readFileSync(new URL("../independent/vectors/migration-v1/migration.json", import.meta.url), "utf8"));
const source = JSON.parse(fs.readFileSync(new URL("../independent/vectors/archive-v1/archive.json", import.meta.url), "utf8"));
const trust = JSON.parse(fs.readFileSync(new URL("../independent/vectors/archive-v1/trusted-policy.json", import.meta.url), "utf8"));
const hash = (algorithm, bytes) => crypto.createHash(algorithm).update(bytes).digest("hex");
const rehashShare = share => {
  const bytes = Buffer.from(share.segment_base64, "base64");
  share.segment_sha512 = hash("sha512", bytes);
  const { root_sha3_512, ...payload } = share;
  share.root_sha3_512 = hash("sha3-512", canonicalJSONStringify(payload));
};

test("each two-share pair recovers the canonical trusted handoff", () => {
  const shares = createEvidenceShards(migration, trust);
  for (const [a, b] of [[0, 1], [0, 2], [1, 2]]) {
    const result = recoverEvidenceShards([shares[a], shares[b]], trust);
    assert.equal(result.recovered, true, result.reason);
    assert.equal(canonicalJSONStringify(result.migration), canonicalJSONStringify(migration));
    assert.equal(verifyEvidenceMigration(result.migration, trust).verified, true);
  }
  assert.equal(recoverEvidenceShards([shares[0]], trust).reason, "two_or_three_shares_required");
});

test("a damaged share can be omitted, but two bad shares cannot be repaired", () => {
  const shares = createEvidenceShards(migration, trust);
  const damaged = structuredClone(shares);
  damaged[0].segment_base64 = "broken";
  assert.equal(recoverEvidenceShards(damaged, trust).recovered, true);
  damaged[1].segment_base64 = "broken";
  assert.equal(recoverEvidenceShards(damaged, trust).reason, "insufficient_valid_shares");
});

test("self-rehashed corruption, mixed metadata, and rollback cannot pass", () => {
  const shares = createEvidenceShards(migration, trust);
  const changed = structuredClone(shares[1]);
  const bytes = Buffer.from(changed.segment_base64, "base64");
  bytes[0] ^= 1;
  changed.segment_base64 = bytes.toString("base64");
  rehashShare(changed);
  assert.equal(recoverEvidenceShards([shares[0], changed], trust).reason, "no_trusted_recovery_pair");
  assert.equal(recoverEvidenceShards([shares[0], changed, shares[2]], trust).recovered, true);

  const mixed = structuredClone(shares[1]);
  mixed.payload_sha512 = "a".repeat(128);
  rehashShare(mixed);
  assert.equal(recoverEvidenceShards([shares[0], mixed], trust).reason, "no_trusted_recovery_pair");
  assert.equal(recoverEvidenceShards([shares[0], shares[1]], null).reason, "external_trust_required");
  const fork = { ...trust, accepted_head: { sequence: 2, root_sha3_512: "a".repeat(128) } };
  assert.equal(recoverEvidenceShards([shares[0], shares[1]], fork).reason, "no_trusted_recovery_pair");
});

test("odd byte count preserves exact length and refuses unverified source", () => {
  const capsule = JSON.parse(Buffer.from(source.capsule_base64, "base64").toString("utf8"));
  const privateKey = crypto.generateKeyPairSync("ed25519").privateKey.export({ type: "pkcs8", format: "pem" });
  const entries = [];
  let previous;
  for (let sequence = 1; sequence <= 10; sequence++) {
    const created_at = new Date(Date.UTC(2026, 9, 10, 0, sequence)).toISOString();
    const record = createEvidenceRenewal(capsule, { sequence, previous_root_sha3_512: previous, created_at });
    entries.push({ record, witnesses: [attestEvidenceRenewal(record, privateKey, { signer: "synthetic", signed_at: created_at })] });
    previous = record.root_sha3_512;
  }
  const policy = { threshold: 1, trusted_fingerprints: [entries[0].witnesses[0].public_key_fingerprint_sha256],
    accepted_head: { sequence: 10, root_sha3_512: previous } };
  const variant = createEvidenceMigration(createEvidenceArchive(capsule, entries, policy), policy);
  assert.equal(Buffer.byteLength(canonicalJSONStringify(variant)) % 2, 1);
  const shards = createEvidenceShards(variant, policy);
  for (const pair of [[0, 1], [0, 2], [1, 2]]) {
    assert.equal(canonicalJSONStringify(recoverEvidenceShards(pair.map(i => shards[i]), policy).migration),
      canonicalJSONStringify(variant));
  }
  assert.throws(() => createEvidenceShards({ ...variant, root_sha512: "0".repeat(128) }, policy),
    /UNVERIFIED_HANDOFF/);
});
