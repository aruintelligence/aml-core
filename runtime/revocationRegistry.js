import crypto from "node:crypto";
import { canonicalJSONStringify } from "../protocol/canonicalJson.js";

function sha256(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

export function createRevocationRegistry() {
  return { type: "aml-revocation-registry/1", entries: [], head: null };
}

export function revokeArtifact(registry, artifact_hash, { reason = null, revoked_at = null } = {}) {
  if (!registry || registry.type !== "aml-revocation-registry/1") throw new Error("Invalid revocation registry");
  if (!Array.isArray(registry.entries)) throw new Error("Invalid revocation registry entries");
  if (!artifact_hash) throw new Error("artifact_hash is required");
  const body = {
    index: registry.entries.length,
    previous_hash: registry.head,
    artifact_hash,
    reason,
    revoked_at
  };
  const entry_hash = sha256(canonicalJSONStringify(body));
  return {
    type: registry.type,
    entries: [...registry.entries, { ...body, entry_hash }],
    head: entry_hash
  };
}

export function verifyRevocationRegistry(registry) {
  if (!registry || registry.type !== "aml-revocation-registry/1") return { valid: false, reason: "invalid_type" };
  if (!Array.isArray(registry.entries)) return { valid: false, reason: "invalid_entries" };

  let previous = null;
  for (let i = 0; i < registry.entries.length; i += 1) {
    const entry = registry.entries[i];
    if (!entry || typeof entry !== "object" || Array.isArray(entry)) {
      return { valid: false, reason: "invalid_entry", index: i };
    }

    const { entry_hash, ...body } = entry;
    if (entry.index !== i) return { valid: false, reason: "index_mismatch", index: i };
    if (entry.previous_hash !== previous) return { valid: false, reason: "chain_mismatch", index: i };

    let expectedHash;
    try {
      expectedHash = sha256(canonicalJSONStringify(body));
    } catch {
      return { valid: false, reason: "invalid_entry", index: i };
    }
    if (expectedHash !== entry_hash) return { valid: false, reason: "hash_mismatch", index: i };
    previous = entry_hash;
  }
  if (registry.head !== previous) return { valid: false, reason: "head_mismatch" };
  return { valid: true, reason: null, head: previous, size: registry.entries.length };
}

export function isRevoked(registry, artifact_hash) {
  const verification = verifyRevocationRegistry(registry);
  if (!verification.valid) return { revoked: false, registry_valid: false, reason: verification.reason };
  const entry = [...registry.entries].reverse().find((item) => item.artifact_hash === artifact_hash) ?? null;
  return { revoked: Boolean(entry), registry_valid: true, entry };
}
