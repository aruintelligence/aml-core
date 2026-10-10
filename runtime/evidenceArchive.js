// A single-file, byte-preserving offline container for capsules and renewals.
// The embedded policy is context only; verification requires external trust.
import crypto from "node:crypto";
import { canonicalJSONStringify } from "../protocol/canonicalJson.js";
import { verifyEvidenceCapsule } from "./evidenceCapsule.js";
import { verifyEvidenceRenewalChain } from "./evidenceRenewal.js";

const PROTOCOL = "aml-evidence-archive/1";
const ENCODING = "canonical-json-utf8-base64/1";
const BOUNDARY = "Embedded policy is an archival hint, never a trust source. Supply trusted keys and accepted head separately.";
const README = "ĀML evidence archive v1. Decode each base64 component as UTF-8 canonical JSON. Verify its digest and the archive root, then verify the capsule and renewal signatures using trusted keys and any remembered head obtained outside this archive. policy_hint is historical context, never a trust source. Signed times and integrity hashes do not prove historical truth or independent witnessing.";
const fields = ["protocol", "encoding", "claim_boundary", "readme", "capsule_base64", "renewals_base64", "policy_hint_base64", "summary", "manifest", "root_sha3_512"];
const manifestFields = ["capsule_sha3_512", "renewals_sha3_512", "policy_hint_sha3_512"];
const sha3 = value => crypto.createHash("sha3-512").update(value).digest("hex");
const canonical = value => canonicalJSONStringify(value);
const sameKeys = (value, expected) => value && typeof value === "object" && !Array.isArray(value) && Object.keys(value).sort().join("|") === [...expected].sort().join("|");
const pack = value => Buffer.from(canonical(value), "utf8");

function unpack(encoded) {
  if (typeof encoded !== "string" || !/^[A-Za-z0-9+/]+={0,2}$/.test(encoded)) throw new Error("invalid_base64");
  const bytes = Buffer.from(encoded, "base64");
  if (bytes.toString("base64") !== encoded) throw new Error("noncanonical_base64");
  const parsed = JSON.parse(bytes.toString("utf8"));
  if (!Buffer.from(canonical(parsed), "utf8").equals(bytes)) throw new Error("noncanonical_json");
  return { bytes, parsed };
}

function payloadOf(archive) {
  const { root_sha3_512, ...payload } = archive;
  return payload;
}

function summaryOf(capsule, entries) {
  return {
    receipt_sha256: capsule.receipt.receipt_sha256,
    renewal_count: entries.length,
    head_root_sha3_512: entries.at(-1).record.root_sha3_512
  };
}

export function createEvidenceArchive(capsule, entries, policy) {
  if (!verifyEvidenceCapsule(capsule).verified || !verifyEvidenceRenewalChain(capsule, entries, policy).verified) {
    throw new Error("AML_ARCHIVE_UNVERIFIED_INPUT");
  }
  const capsuleBytes = pack(capsule);
  const renewalBytes = pack(entries);
  const policyBytes = pack(policy);
  const payload = {
    protocol: PROTOCOL,
    encoding: ENCODING,
    claim_boundary: BOUNDARY,
    readme: README,
    capsule_base64: capsuleBytes.toString("base64"),
    renewals_base64: renewalBytes.toString("base64"),
    policy_hint_base64: policyBytes.toString("base64"),
    summary: summaryOf(capsule, entries),
    manifest: {
      capsule_sha3_512: sha3(capsuleBytes),
      renewals_sha3_512: sha3(renewalBytes),
      policy_hint_sha3_512: sha3(policyBytes)
    }
  };
  return { ...payload, root_sha3_512: sha3(pack(payload)) };
}

export function verifyEvidenceArchive(archive, trustedPolicy) {
  const fail = reason => ({ verified: false, reason, policy_hint_trusted: false });
  if (!trustedPolicy) return fail("external_trust_required");
  if (!sameKeys(archive, fields) || archive.protocol !== PROTOCOL || archive.encoding !== ENCODING ||
      archive.claim_boundary !== BOUNDARY || archive.readme !== README || !sameKeys(archive.manifest, manifestFields)) return fail("unsupported_contract");
  try {
    if (archive.root_sha3_512 !== sha3(pack(payloadOf(archive)))) return fail("archive_root_mismatch");
    const capsule = unpack(archive.capsule_base64);
    const renewals = unpack(archive.renewals_base64);
    const hint = unpack(archive.policy_hint_base64);
    if (archive.manifest.capsule_sha3_512 !== sha3(capsule.bytes) ||
        archive.manifest.renewals_sha3_512 !== sha3(renewals.bytes) ||
        archive.manifest.policy_hint_sha3_512 !== sha3(hint.bytes)) return fail("component_digest_mismatch");
    if (!verifyEvidenceCapsule(capsule.parsed).verified) return fail("invalid_capsule");
    const chain = verifyEvidenceRenewalChain(capsule.parsed, renewals.parsed, trustedPolicy);
    if (!chain.verified) return fail(`renewal_${chain.reason}`);
    if (canonical(archive.summary) !== canonical(summaryOf(capsule.parsed, renewals.parsed))) return fail("summary_mismatch");
    return { verified: true, reason: null, policy_hint_trusted: false, receipt_sha256: archive.summary.receipt_sha256,
      renewal_count: chain.sequence, head_root_sha3_512: chain.head_root_sha3_512, freshness_bound: chain.freshness_bound };
  } catch {
    return fail("malformed_archive");
  }
}
