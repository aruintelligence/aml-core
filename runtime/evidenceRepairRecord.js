// A deterministic audit aid. It binds a repaired share to the inputs that
// reproduced it, but does not attest custody, storage placement, or time.
import crypto from "node:crypto";
import { canonicalJSONStringify } from "../protocol/canonicalJson.js";
import { repairEvidenceShare } from "./evidenceShards.js";

const PROTOCOL = "aml-evidence-repair-record/1";
const BOUNDARY = "A project-authored local reconstruction record; not an independent witness, custody proof, trusted timestamp, or physical storage guarantee.";
const pack = value => Buffer.from(canonicalJSONStringify(value), "utf8");
const hash = (algorithm, value) => crypto.createHash(algorithm).update(value).digest("hex");

export function createEvidenceRepairRecord(survivors, replacement, trustedPolicy) {
  const repair = repairEvidenceShare(survivors, trustedPolicy);
  if (!repair.repaired) throw new Error(`AML_REPAIR_RECORD_${repair.reason}`);
  if (canonicalJSONStringify(replacement) !== canonicalJSONStringify(repair.share)) {
    throw new Error("AML_REPAIR_RECORD_REPLACEMENT_MISMATCH");
  }
  const ordered = [...survivors].sort((a, b) => a.index - b.index);
  const payload = {
    protocol: PROTOCOL, claim_boundary: BOUNDARY,
    survivor_indices: ordered.map(share => share.index),
    survivor_roots_sha3_512: ordered.map(share => share.root_sha3_512),
    replacement_index: repair.missing_index,
    replacement_root_sha3_512: replacement.root_sha3_512,
    payload_sha512: repair.payload_sha512,
    migration_root_sha3_512: replacement.migration_root_sha3_512,
    policy_sha256: hash("sha256", pack(trustedPolicy)),
    accepted_head: { sequence: trustedPolicy.accepted_head.sequence,
      root_sha3_512: trustedPolicy.accepted_head.root_sha3_512 },
    verified_pairs: 3, policy_hint_trusted: false
  };
  return { ...payload, root_sha3_512: hash("sha3-512", pack(payload)) };
}

export function verifyEvidenceRepairRecord(record, survivors, replacement, trustedPolicy) {
  const fail = reason => ({ verified: false, reason, policy_hint_trusted: false });
  try {
    const expected = createEvidenceRepairRecord(survivors, replacement, trustedPolicy);
    if (canonicalJSONStringify(record) !== canonicalJSONStringify(expected)) return fail("record_mismatch");
    return { verified: true, reason: null, policy_hint_trusted: false,
      root_sha3_512: expected.root_sha3_512, replacement_index: expected.replacement_index,
      payload_sha512: expected.payload_sha512 };
  } catch (error) {
    return fail(error.message.startsWith("AML_REPAIR_RECORD_") ? error.message.slice(18).toLowerCase() : "invalid_input");
  }
}
