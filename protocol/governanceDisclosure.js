import crypto from "node:crypto";
import { canonicalJSONStringify } from "./canonicalJson.js";
import { verifyGovernanceStreamTranscript } from "./governanceTranscript.js";
import { buildReceiptMerkleTree, createReceiptInclusionProof, verifyReceiptInclusionProof } from "../runtime/receiptMerkle.js";

export const AML_GOVERNANCE_DISCLOSURE = "aml-governance-selective-disclosure/1";
export const AML_GOVERNANCE_DISCLOSURE_VERIFICATION = "aml-governance-selective-disclosure-verification/1";

function entryHash(entry) {
  const material = {
    sequence: entry.sequence,
    direction: entry.direction,
    previous_sha256: entry.previous_sha256,
    message: entry.message
  };
  return crypto.createHash("sha256").update(canonicalJSONStringify(material)).digest("hex");
}

function normalizeIndices(indices, count) {
  if (!Array.isArray(indices) || indices.length === 0) throw new Error("at least one disclosure index is required");
  return [...new Set(indices)].sort((a, b) => a - b).map(index => {
    if (!Number.isInteger(index) || index < 0 || index >= count) throw new RangeError(`disclosure index ${index} is out of range`);
    return index;
  });
}

export function createGovernanceDisclosure(transcript, indices) {
  const verification = verifyGovernanceStreamTranscript(transcript);
  if (!verification.valid) throw new Error(`refusing to disclose from invalid transcript: ${verification.errors.join("; ")}`);
  const selected = normalizeIndices(indices, transcript.entries.length);
  const tree = buildReceiptMerkleTree(transcript.entries.map(entry => entry.entry_sha256));
  return {
    protocol: AML_GOVERNANCE_DISCLOSURE,
    source_transcript_protocol: transcript.protocol,
    source_transcript_root_sha256: transcript.root_sha256,
    source_entry_count: transcript.entries.length,
    disclosure_merkle_root_sha256: tree.root_sha256,
    disclosed_entries: selected.map(index => ({
      index,
      entry: structuredClone(transcript.entries[index]),
      inclusion_proof: createReceiptInclusionProof(tree, index)
    })),
    leakage_notice: "This proof hides undisclosed message bodies but still reveals transcript entry count, selected indices, disclosed entries, the transcript root, and a Merkle commitment to all entry hashes."
  };
}

export function verifyGovernanceDisclosure(disclosure, options = {}) {
  const errors = [];
  if (!disclosure || disclosure.protocol !== AML_GOVERNANCE_DISCLOSURE) {
    return { protocol: AML_GOVERNANCE_DISCLOSURE_VERIFICATION, valid: false, errors: ["unsupported disclosure protocol"] };
  }
  if (!Array.isArray(disclosure.disclosed_entries) || disclosure.disclosed_entries.length === 0) errors.push("no disclosed entries");

  const seen = new Set();
  const entry_results = [];
  for (const item of disclosure.disclosed_entries || []) {
    const itemErrors = [];
    if (!Number.isInteger(item.index) || item.index < 0 || item.index >= disclosure.source_entry_count) itemErrors.push("invalid disclosed index");
    if (seen.has(item.index)) itemErrors.push("duplicate disclosed index");
    seen.add(item.index);

    let calculatedEntryHash = null;
    try {
      calculatedEntryHash = entryHash(item.entry);
      if (calculatedEntryHash !== item.entry?.entry_sha256) itemErrors.push("disclosed entry hash mismatch");
    } catch {
      itemErrors.push("invalid disclosed entry");
    }

    const proofResult = verifyReceiptInclusionProof(item.inclusion_proof);
    if (!proofResult.verified) itemErrors.push(`invalid inclusion proof: ${proofResult.reason}`);
    if (item.inclusion_proof?.index !== item.index) itemErrors.push("proof index mismatch");
    if (item.inclusion_proof?.leaf !== item.entry?.entry_sha256) itemErrors.push("proof leaf does not match disclosed entry");
    if (item.inclusion_proof?.root_sha256 !== disclosure.disclosure_merkle_root_sha256) itemErrors.push("proof root does not match disclosure commitment");

    entry_results.push({ index: item.index, valid: itemErrors.length === 0, calculated_entry_sha256: calculatedEntryHash, errors: itemErrors });
    errors.push(...itemErrors.map(error => `entry ${item.index}: ${error}`));
  }

  if (options.expected_merkle_root && disclosure.disclosure_merkle_root_sha256 !== options.expected_merkle_root) {
    errors.push("disclosure Merkle root does not match externally expected root");
  }
  if (options.expected_transcript_root && disclosure.source_transcript_root_sha256 !== options.expected_transcript_root) {
    errors.push("source transcript root does not match externally expected root");
  }

  return {
    protocol: AML_GOVERNANCE_DISCLOSURE_VERIFICATION,
    valid: errors.length === 0,
    source_transcript_root_sha256: disclosure.source_transcript_root_sha256 ?? null,
    disclosure_merkle_root_sha256: disclosure.disclosure_merkle_root_sha256 ?? null,
    disclosed_count: disclosure.disclosed_entries?.length ?? 0,
    entry_results,
    externally_anchored: Boolean(options.expected_merkle_root || options.expected_transcript_root),
    errors,
    claim_boundary: "A valid selective-disclosure proof demonstrates membership in the supplied Merkle commitment. Authenticity requires that the commitment or transcript root be obtained from an independently trusted, signed, witnessed, or otherwise authenticated source."
  };
}
