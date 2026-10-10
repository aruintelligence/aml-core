// Portable, self-contained preservation of an ĀML execution receipt.
// A capsule proves integrity of the bytes it carries, not independent truth or permanence.
import crypto from "node:crypto";
import { canonicalJSONStringify } from "../protocol/canonicalJson.js";
import { verifyExecutionReceipt, verifySignedExecutionReceipt } from "../compiler/accountablePipeline.js";

const PROTOCOL = "aml-evidence-capsule/1";
const CONTRACT = "aml-sorted-json/1";
const CLAIM_BOUNDARY = "Project-authored declared inputs. Integrity is not authenticity, independent validation, or proof of human impact.";
const keys = ["protocol", "canonicalization", "claim_boundary", "summary", "receipt", "digests"];
const digest = (algorithm, bytes) => crypto.createHash(algorithm).update(bytes, "utf8").digest("hex");

function summaryOf(receipt) {
  return {
    timestamp: receipt.timestamp,
    profile_id: receipt.profile.id,
    allowed: receipt.selected_render.allowed,
    suppressed: receipt.selected_render.suppressed,
    receipt_sha256: receipt.receipt_sha256,
    signed: receipt.signature !== undefined
  };
}

function material(capsule) {
  const { digests, ...payload } = capsule;
  return payload;
}

export function createEvidenceCapsule(receipt) {
  if (!verifyExecutionReceipt(receipt).verified) throw new Error("AML_CAPSULE_INVALID_RECEIPT");
  if (receipt.signature && !verifySignedExecutionReceipt(receipt).verified) {
    throw new Error("AML_CAPSULE_INVALID_SIGNATURE");
  }
  // Canonical round trip rejects undefined, non-finite values and non-JSON objects.
  const embedded = JSON.parse(canonicalJSONStringify(receipt));
  const payload = {
    protocol: PROTOCOL,
    canonicalization: CONTRACT,
    claim_boundary: CLAIM_BOUNDARY,
    summary: summaryOf(embedded),
    receipt: embedded
  };
  const bytes = canonicalJSONStringify(payload);
  return {
    ...payload,
    digests: { sha256: digest("sha256", bytes), sha512: digest("sha512", bytes) }
  };
}

export function verifyEvidenceCapsule(capsule) {
  const failure = (reason) => ({ verified: false, reason });
  if (!capsule || typeof capsule !== "object" || Array.isArray(capsule)) return failure("invalid_capsule");
  if (capsule.protocol !== PROTOCOL || capsule.canonicalization !== CONTRACT) return failure("unsupported_contract");
  if (Object.keys(capsule).sort().join("|") !== [...keys].sort().join("|")) return failure("unexpected_fields");
  if (capsule.claim_boundary !== CLAIM_BOUNDARY) return failure("claim_boundary_changed");
  if (!capsule.digests || Object.keys(capsule.digests).sort().join("|") !== "sha256|sha512") return failure("invalid_digests");
  try {
    const bytes = canonicalJSONStringify(material(capsule));
    if (capsule.digests.sha256 !== digest("sha256", bytes) || capsule.digests.sha512 !== digest("sha512", bytes)) return failure("digest_mismatch");
    if (!capsule.receipt || !verifyExecutionReceipt(capsule.receipt).verified) return failure("invalid_receipt");
    if (capsule.receipt.signature && !verifySignedExecutionReceipt(capsule.receipt).verified) return failure("invalid_signature");
    if (canonicalJSONStringify(capsule.summary) !== canonicalJSONStringify(summaryOf(capsule.receipt))) return failure("summary_mismatch");
    return { verified: true, reason: null, receipt_sha256: capsule.receipt.receipt_sha256, signed: capsule.summary.signed };
  } catch {
    return failure("malformed_payload");
  }
}
