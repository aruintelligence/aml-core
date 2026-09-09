import crypto from "node:crypto";
import { canonicalJSONStringify } from "../protocol/canonicalJson.js";

function hash(value) {
  return crypto.createHash("sha256").update(typeof value === "string" ? value : canonicalJSONStringify(value)).digest("hex");
}

export function createProofCarryingInterface({ html, receipt = null, policy_passport = null, conformance_claim = null, provenance = null, causal_graph = null } = {}) {
  if (typeof html !== "string") throw new Error("html is required");
  const body = {
    type: "aml-proof-carrying-interface/1",
    output_sha256: hash(html),
    receipt_sha256: receipt ? hash(receipt) : null,
    policy_passport_sha256: policy_passport ? hash(policy_passport) : null,
    conformance_claim_sha256: conformance_claim ? hash(conformance_claim) : null,
    provenance_sha256: provenance ? hash(provenance) : null,
    causal_graph_sha256: causal_graph ? hash(causal_graph) : null
  };
  return { ...body, manifest_sha256: hash(body) };
}

export function verifyProofCarryingInterface(manifest, { html, receipt = null, policy_passport = null, conformance_claim = null, provenance = null, causal_graph = null } = {}) {
  if (!manifest || manifest.type !== "aml-proof-carrying-interface/1") return { valid: false, reason: "invalid_type" };
  const { manifest_sha256, ...body } = manifest;

  let manifestHash;
  try {
    manifestHash = hash(body);
  } catch {
    return { valid: false, reason: "invalid_manifest" };
  }
  if (manifestHash !== manifest_sha256) return { valid: false, reason: "manifest_hash_mismatch" };
  if (typeof html !== "string" || hash(html) !== manifest.output_sha256) return { valid: false, reason: "output_mismatch" };

  const checks = [
    ["receipt_sha256", receipt],
    ["policy_passport_sha256", policy_passport],
    ["conformance_claim_sha256", conformance_claim],
    ["provenance_sha256", provenance],
    ["causal_graph_sha256", causal_graph]
  ];
  for (const [field, value] of checks) {
    if (manifest[field] === null && value == null) continue;
    if (manifest[field] === null || value == null) return { valid: false, reason: `${field}_mismatch` };

    let valueHash;
    try {
      valueHash = hash(value);
    } catch {
      return { valid: false, reason: `${field}_invalid` };
    }
    if (valueHash !== manifest[field]) return { valid: false, reason: `${field}_mismatch` };
  }

  return { valid: true, reason: null, manifest_sha256 };
}
