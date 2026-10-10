// Repairable physical carrier for a verified handoff. Shares provide no secrecy
// or authenticity. Every reconstructed handoff is verified under external trust.
import crypto from "node:crypto";
import { canonicalJSONStringify } from "../protocol/canonicalJson.js";
import { verifyEvidenceMigration } from "./evidenceMigration.js";

const PROTOCOL = "aml-evidence-shard/1";
const ENCODING = "canonical-json-utf8-base64/1";
const SCHEME = "xor-2-of-3/1";
const BOUNDARY = "Any two distinct shares repair one missing share. This is redundancy, not secrecy, trusted identity, or a future cryptographic guarantee.";
const FIELDS = ["protocol", "encoding", "scheme", "claim_boundary", "index", "total_bytes", "segment_bytes",
  "payload_sha512", "migration_root_sha3_512", "migration_root_sha512", "segment_base64",
  "segment_sha512", "root_sha3_512"];
const META = ["protocol", "encoding", "scheme", "claim_boundary", "total_bytes", "segment_bytes",
  "payload_sha512", "migration_root_sha3_512", "migration_root_sha512"];
const pack = value => Buffer.from(canonicalJSONStringify(value), "utf8");
const hash = (algorithm, value) => crypto.createHash(algorithm).update(value).digest("hex");
const sameKeys = (value, keys) => value && typeof value === "object" && !Array.isArray(value) &&
  Object.keys(value).sort().join("|") === [...keys].sort().join("|");

function xor(a, b) {
  const result = Buffer.alloc(a.length);
  for (let i = 0; i < result.length; i++) result[i] = a[i] ^ b[i];
  return result;
}

function readShare(share) {
  if (!sameKeys(share, FIELDS) || share.protocol !== PROTOCOL || share.encoding !== ENCODING ||
      share.scheme !== SCHEME || share.claim_boundary !== BOUNDARY ||
      !Number.isSafeInteger(share.index) || share.index < 0 || share.index > 2 ||
      !Number.isSafeInteger(share.total_bytes) || share.total_bytes < 1 ||
      !Number.isSafeInteger(share.segment_bytes) || share.segment_bytes !== Math.ceil(share.total_bytes / 2) ||
      ![share.payload_sha512, share.migration_root_sha3_512, share.migration_root_sha512,
        share.segment_sha512, share.root_sha3_512].every(value => typeof value === "string" && /^[a-f0-9]{128}$/.test(value)) ||
      typeof share.segment_base64 !== "string" ||
      !/^[A-Za-z0-9+/]+={0,2}$/.test(share.segment_base64)) return null;
  try {
    const bytes = Buffer.from(share.segment_base64, "base64");
    if (bytes.length !== share.segment_bytes || bytes.toString("base64") !== share.segment_base64 ||
        share.segment_sha512 !== hash("sha512", bytes)) return null;
    const { root_sha3_512, ...payload } = share;
    if (root_sha3_512 !== hash("sha3-512", pack(payload))) return null;
    return { share, bytes };
  } catch {
    return null;
  }
}

function assemble(left, right) {
  const a = left.share.index < right.share.index ? left : right;
  const b = a === left ? right : left;
  const metaA = Object.fromEntries(META.map(key => [key, a.share[key]]));
  const metaB = Object.fromEntries(META.map(key => [key, b.share[key]]));
  if (canonicalJSONStringify(metaA) !== canonicalJSONStringify(metaB)) return null;
  const first = a.share.index === 0 ? a.bytes : xor(a.bytes, b.bytes);
  const second = a.share.index === 1 ? a.bytes : b.share.index === 1 ? b.bytes : xor(a.bytes, b.bytes);
  const data = Buffer.concat([first, second]).subarray(0, a.share.total_bytes);
  if (hash("sha512", data) !== a.share.payload_sha512) return null;
  try {
    const migration = JSON.parse(data.toString("utf8"));
    if (!pack(migration).equals(data) || migration.root_sha3_512 !== a.share.migration_root_sha3_512 ||
        migration.root_sha512 !== a.share.migration_root_sha512) return null;
    return migration;
  } catch {
    return null;
  }
}

export function createEvidenceShards(migration, trustedPolicy) {
  if (!verifyEvidenceMigration(migration, trustedPolicy).verified) throw new Error("AML_SHARDS_UNVERIFIED_HANDOFF");
  const data = pack(migration);
  const size = Math.ceil(data.length / 2);
  const first = Buffer.alloc(size);
  const second = Buffer.alloc(size);
  data.copy(first, 0, 0, size);
  data.copy(second, 0, size);
  const segments = [first, second, xor(first, second)];
  return segments.map((bytes, index) => {
    const payload = {
      protocol: PROTOCOL, encoding: ENCODING, scheme: SCHEME, claim_boundary: BOUNDARY,
      index, total_bytes: data.length, segment_bytes: size,
      payload_sha512: hash("sha512", data),
      migration_root_sha3_512: migration.root_sha3_512,
      migration_root_sha512: migration.root_sha512,
      segment_base64: bytes.toString("base64"),
      segment_sha512: hash("sha512", bytes)
    };
    return { ...payload, root_sha3_512: hash("sha3-512", pack(payload)) };
  });
}

export function recoverEvidenceShards(shares, trustedPolicy) {
  const fail = reason => ({ recovered: false, reason, policy_hint_trusted: false });
  if (!trustedPolicy) return fail("external_trust_required");
  if (!Array.isArray(shares) || shares.length < 2 || shares.length > 3) return fail("two_or_three_shares_required");
  const valid = shares.map(readShare).filter(Boolean);
  if (valid.length < 2) return fail("insufficient_valid_shares");
  const candidates = [];
  for (let i = 0; i < valid.length; i++) {
    for (let j = i + 1; j < valid.length; j++) {
      if (valid[i].share.index === valid[j].share.index) continue;
      const migration = assemble(valid[i], valid[j]);
      if (migration && verifyEvidenceMigration(migration, trustedPolicy).verified) candidates.push(migration);
    }
  }
  if (!candidates.length) return fail("no_trusted_recovery_pair");
  if (candidates.some(candidate => canonicalJSONStringify(candidate) !== canonicalJSONStringify(candidates[0]))) {
    return fail("ambiguous_recovery");
  }
  return { recovered: true, reason: null, policy_hint_trusted: false,
    migration: candidates[0], payload_sha512: hash("sha512", pack(candidates[0])),
    shares_examined: shares.length, valid_pairs: candidates.length };
}
