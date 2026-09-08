import crypto from "node:crypto";
import { canonicalJSONStringify } from "../protocol/canonicalJson.js";

function sha256(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

export function createTrustDelegation({ issuer, delegate, capabilities = [], issued_at = null, expires_at = null } = {}) {
  if (!issuer || !delegate) throw new Error("issuer and delegate are required");
  const body = {
    type: "aml-trust-delegation/1",
    issuer,
    delegate,
    capabilities: [...new Set(capabilities)].sort(),
    issued_at,
    expires_at
  };
  return { ...body, delegation_hash: sha256(canonicalJSONStringify(body)) };
}

export function verifyTrustDelegation(delegation, { now = null, requiredCapability = null } = {}) {
  if (!delegation || delegation.type !== "aml-trust-delegation/1") return { valid: false, reason: "invalid_type" };
  const { delegation_hash, ...body } = delegation;
  if (sha256(canonicalJSONStringify(body)) !== delegation_hash) return { valid: false, reason: "hash_mismatch" };
  if (now && delegation.expires_at && new Date(now) >= new Date(delegation.expires_at)) return { valid: false, reason: "expired" };
  if (requiredCapability && !delegation.capabilities.includes(requiredCapability)) return { valid: false, reason: "capability_not_delegated" };
  return { valid: true, reason: null, delegation_hash };
}

export function verifyDelegationChain(chain, { rootIssuer = null, now = null, requiredCapability = null } = {}) {
  if (!Array.isArray(chain) || chain.length === 0) return { valid: false, reason: "empty_chain" };
  for (let i = 0; i < chain.length; i += 1) {
    const result = verifyTrustDelegation(chain[i], { now, requiredCapability });
    if (!result.valid) return { valid: false, reason: result.reason, index: i };
    if (i > 0 && chain[i - 1].delegate !== chain[i].issuer) return { valid: false, reason: "broken_chain", index: i };
  }
  if (rootIssuer && chain[0].issuer !== rootIssuer) return { valid: false, reason: "unexpected_root" };
  return { valid: true, reason: null, leaf: chain.at(-1).delegate };
}
