// Transparent v1 -> v2 preservation handoff. Retain the entire v1 archive.
// Repacking does not make old cryptography stronger or establish new history.
import crypto from "node:crypto";
import { canonicalJSONStringify } from "../protocol/canonicalJson.js";
import { verifyEvidenceArchive } from "./evidenceArchive.js";

const PROTOCOL = "aml-evidence-migration/1";
const ENCODING = "canonical-json-utf8-base64/2";
const BOUNDARY = "A lossless format handoff, not a cryptographic security upgrade. Original v1 bytes and external trust remain necessary.";
const README = "ĀML migration handoff v1 retains a canonical v1 archive in source_archive_base64 and repeats its three components in a versioned v2 layout. Verify both roots, each component digest, exact component equivalence, and the embedded v1 archive with trust supplied outside this file. The archive policy hint never establishes trust. Preserve this handoff alongside the original archive and its trust history.";
const fields = ["protocol", "encoding", "claim_boundary", "readme", "source_archive_base64", "capsule_base64", "renewals_base64", "policy_hint_base64", "summary", "manifest", "root_sha3_512", "root_sha512"];
const parts = ["source_archive", "capsule", "renewals", "policy_hint"];
const manifestFields = parts.flatMap(part => [`${part}_sha3_512`, `${part}_sha512`]);
const canonical = value => canonicalJSONStringify(value);
const pack = value => Buffer.from(canonical(value), "utf8");
const digest = (algorithm, value) => crypto.createHash(algorithm).update(value).digest("hex");
const sameKeys = (value, expected) => value && typeof value === "object" && !Array.isArray(value) &&
  Object.keys(value).sort().join("|") === [...expected].sort().join("|");

function unpack(encoded) {
  if (typeof encoded !== "string" || !/^[A-Za-z0-9+/]+={0,2}$/.test(encoded)) throw new Error("invalid_base64");
  const bytes = Buffer.from(encoded, "base64");
  if (bytes.toString("base64") !== encoded) throw new Error("noncanonical_base64");
  const parsed = JSON.parse(bytes.toString("utf8"));
  if (!pack(parsed).equals(bytes)) throw new Error("noncanonical_json");
  return { bytes, parsed };
}

function summaryOf(source) {
  return { source_archive_root_sha3_512: source.root_sha3_512, ...source.summary };
}

function manifestOf(bytes) {
  return Object.fromEntries(parts.flatMap(part => [
    [`${part}_sha3_512`, digest("sha3-512", bytes[part])],
    [`${part}_sha512`, digest("sha512", bytes[part])]
  ]));
}

function receiptTrust(source, policy) {
  const capsule = JSON.parse(Buffer.from(source.capsule_base64, "base64").toString("utf8"));
  if (!capsule.summary.signed) return null;
  const signature = capsule.receipt.signature;
  if (signature?.version !== "1.1") return "unsupported_receipt_signature";
  if (!Array.isArray(policy.trusted_receipt_fingerprints) || policy.trusted_receipt_fingerprints.length === 0) return "external_receipt_trust_required";
  if (!Array.isArray(policy.revoked_receipt_fingerprints ?? []) ||
      policy.trusted_receipt_fingerprints.some(value => typeof value !== "string") ||
      (policy.revoked_receipt_fingerprints ?? []).some(value => typeof value !== "string")) return "invalid_receipt_trust_policy";
  if (policy.revoked_receipt_fingerprints?.includes(signature.public_key_sha256)) return "receipt_signer_revoked";
  if (!policy.trusted_receipt_fingerprints.includes(signature.public_key_sha256)) return "receipt_signer_untrusted";
  return null;
}

export function createEvidenceMigration(sourceArchive, trustedPolicy) {
  if (!verifyEvidenceArchive(sourceArchive, trustedPolicy).verified) throw new Error("AML_MIGRATION_UNVERIFIED_SOURCE");
  const trustError = receiptTrust(sourceArchive, trustedPolicy);
  if (trustError) throw new Error(`AML_MIGRATION_${trustError.toUpperCase()}`);
  const bytes = {
    source_archive: pack(sourceArchive),
    capsule: Buffer.from(sourceArchive.capsule_base64, "base64"),
    renewals: Buffer.from(sourceArchive.renewals_base64, "base64"),
    policy_hint: Buffer.from(sourceArchive.policy_hint_base64, "base64")
  };
  const payload = {
    protocol: PROTOCOL,
    encoding: ENCODING,
    claim_boundary: BOUNDARY,
    readme: README,
    source_archive_base64: bytes.source_archive.toString("base64"),
    capsule_base64: bytes.capsule.toString("base64"),
    renewals_base64: bytes.renewals.toString("base64"),
    policy_hint_base64: bytes.policy_hint.toString("base64"),
    summary: summaryOf(sourceArchive),
    manifest: manifestOf(bytes)
  };
  const material = pack(payload);
  return { ...payload, root_sha3_512: digest("sha3-512", material), root_sha512: digest("sha512", material) };
}

export function verifyEvidenceMigration(migration, trustedPolicy) {
  const fail = reason => ({ verified: false, reason, policy_hint_trusted: false });
  if (!trustedPolicy) return fail("external_trust_required");
  if (!sameKeys(migration, fields) || migration.protocol !== PROTOCOL || migration.encoding !== ENCODING ||
      migration.claim_boundary !== BOUNDARY || migration.readme !== README ||
      !sameKeys(migration.manifest, manifestFields)) return fail("unsupported_contract");
  try {
    const { root_sha3_512, root_sha512, ...payload } = migration;
    const material = pack(payload);
    if (root_sha3_512 !== digest("sha3-512", material) || root_sha512 !== digest("sha512", material)) return fail("migration_root_mismatch");
    const decoded = Object.fromEntries(parts.map(part => [part, unpack(migration[`${part}_base64`])]));
    const bytes = Object.fromEntries(parts.map(part => [part, decoded[part].bytes]));
    if (canonical(migration.manifest) !== canonical(manifestOf(bytes))) return fail("component_digest_mismatch");
    const source = decoded.source_archive.parsed;
    const original = verifyEvidenceArchive(source, trustedPolicy);
    if (!original.verified) return fail(`source_${original.reason}`);
    const trustError = receiptTrust(source, trustedPolicy);
    if (trustError) return fail(trustError);
    if (parts.slice(1).some(part => source[`${part}_base64`] !== migration[`${part}_base64`])) return fail("component_equivalence_mismatch");
    if (canonical(migration.summary) !== canonical(summaryOf(source))) return fail("summary_mismatch");
    return { verified: true, reason: null, policy_hint_trusted: false, source_archive_root_sha3_512: source.root_sha3_512,
      migration_root_sha3_512: root_sha3_512, migration_root_sha512: root_sha512,
      receipt_sha256: original.receipt_sha256, renewal_count: original.renewal_count,
      freshness_bound: original.freshness_bound, component_equivalent: true };
  } catch {
    return fail("malformed_migration");
  }
}
