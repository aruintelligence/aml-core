import crypto from "node:crypto";
import { canonicalJSONStringify } from "../protocol/canonicalJson.js";

export const AML_CONFORMANCE_LEVELS = {
  core: ["meaning-tree", "render-decision"],
  accountable: ["meaning-tree", "render-decision", "execution-receipt", "view-meaning"],
  federated: ["meaning-tree", "render-decision", "execution-receipt", "view-meaning", "policy-passport", "content-addressed-bundle", "causal-execution-graph"],
  verifiable: ["meaning-tree", "render-decision", "execution-receipt", "view-meaning", "policy-passport", "content-addressed-bundle", "causal-execution-graph", "selective-disclosure"]
};

const ORDER = ["core", "accountable", "federated", "verifiable"];

function sha256(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

export function evaluateConformanceLevel(capabilities = []) {
  const set = new Set(capabilities);
  let level = null;
  for (const candidate of ORDER) {
    if (AML_CONFORMANCE_LEVELS[candidate].every((capability) => set.has(capability))) level = candidate;
    else break;
  }
  return {
    level,
    missing_for_next: level === "verifiable"
      ? []
      : AML_CONFORMANCE_LEVELS[ORDER[ORDER.indexOf(level) + 1] ?? "core"].filter((capability) => !set.has(capability))
  };
}

export function createConformanceClaim({ implementation, implementation_version, language_version, wire_version, capabilities = [], issued_at = null } = {}) {
  if (!implementation) throw new Error("implementation is required");
  const result = evaluateConformanceLevel(capabilities);
  const body = {
    type: "aml-conformance-claim/1",
    implementation,
    implementation_version: implementation_version ?? null,
    language_version: language_version ?? null,
    wire_version: wire_version ?? null,
    level: result.level,
    capabilities: [...new Set(capabilities)].sort(),
    issued_at
  };
  return { ...body, claim_hash: sha256(canonicalJSONStringify(body)) };
}

export function verifyConformanceClaim(claim) {
  if (!claim || claim.type !== "aml-conformance-claim/1") return { valid: false, reason: "invalid_type" };
  const { claim_hash, ...body } = claim;
  if (sha256(canonicalJSONStringify(body)) !== claim_hash) return { valid: false, reason: "hash_mismatch" };
  const evaluated = evaluateConformanceLevel(claim.capabilities);
  if (evaluated.level !== claim.level) return { valid: false, reason: "level_mismatch" };
  return { valid: true, reason: null, level: claim.level, claim_hash };
}
