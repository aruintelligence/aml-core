import crypto from "node:crypto";
import { canonicalJSONStringify } from "./canonicalJson.js";

export const AML_RUNTIME_DISAGREEMENT_REPORT = "aml-runtime-disagreement-report/1";

function sha256(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function normalizeEntry(entry) {
  if (!entry || typeof entry !== "object") return null;
  return {
    direction: entry.direction ?? null,
    message: entry.message ?? null
  };
}

function classifyDivergence(left, right) {
  if (left == null || right == null) return "missing-entry";
  if (left.direction !== right.direction) return "direction-mismatch";
  const lp = left.message?.protocol ?? null;
  const rp = right.message?.protocol ?? null;
  if (lp !== rp) return "protocol-mismatch";
  if (lp === "aml-governance-stream-decision/1") return "decision-mismatch";
  if (left.direction === "input") return "input-mismatch";
  return "output-mismatch";
}

export function localizeRuntimeDisagreement(leftTranscript, rightTranscript, options = {}) {
  const leftEntries = Array.isArray(leftTranscript?.entries) ? leftTranscript.entries : [];
  const rightEntries = Array.isArray(rightTranscript?.entries) ? rightTranscript.entries : [];
  const max = Math.max(leftEntries.length, rightEntries.length);
  let first = null;

  for (let index = 0; index < max; index += 1) {
    const left = normalizeEntry(leftEntries[index]);
    const right = normalizeEntry(rightEntries[index]);
    const equal = canonicalJSONStringify(left) === canonicalJSONStringify(right);
    if (!equal) {
      first = {
        sequence: index + 1,
        divergence_type: classifyDivergence(left, right),
        left,
        right,
        left_sha256: sha256(canonicalJSONStringify(left)),
        right_sha256: sha256(canonicalJSONStringify(right))
      };
      break;
    }
  }

  const sameRoot = leftTranscript?.root_sha256 != null && leftTranscript.root_sha256 === rightTranscript?.root_sha256;
  const sameLength = leftEntries.length === rightEntries.length;
  const equivalent = first == null && sameLength;

  return {
    protocol: AML_RUNTIME_DISAGREEMENT_REPORT,
    equivalent,
    same_root: sameRoot,
    same_entry_count: sameLength,
    left_root_sha256: leftTranscript?.root_sha256 ?? null,
    right_root_sha256: rightTranscript?.root_sha256 ?? null,
    left_runtime: options.left_runtime ?? null,
    right_runtime: options.right_runtime ?? null,
    first_divergence: first,
    compared_entries: Math.min(leftEntries.length, rightEntries.length),
    claim_boundary: "Localization identifies the first observable transcript disagreement; it does not determine which runtime is semantically correct without an external contract, oracle, or adjudication policy."
  };
}
