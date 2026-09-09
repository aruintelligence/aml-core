import crypto from "node:crypto";
import { canonicalJSONStringify } from "../protocol/canonicalJson.js";
import { verifySemanticReleaseProof } from "../compiler/semanticReleaseProof.js";

export const RELEASE_KEY_TRUST_POLICY_PROTOCOL = "aml-release-key-trust-policy/1";
export const RELEASE_KEY_TRUST_POLICY_MATERIAL_PROTOCOL = "aml-release-key-trust-policy-material/1";

function validHash(value) {
  return typeof value === "string" && /^[a-f0-9]{64}$/.test(value);
}

function normalizeEntry(entry) {
  if (!entry || typeof entry !== "object" || Array.isArray(entry)) throw new TypeError("trusted_keys entries must be objects");
  if (!validHash(entry.public_key_sha256)) throw new TypeError("trusted key fingerprint must be lowercase SHA-256 hex");
  if (entry.signer !== undefined && entry.signer !== null && typeof entry.signer !== "string") throw new TypeError("trusted key signer must be string or null");
  return {
    public_key_sha256: entry.public_key_sha256,
    signer: entry.signer ?? null
  };
}

function compareEntries(a, b) {
  if (a.public_key_sha256 !== b.public_key_sha256) return a.public_key_sha256 < b.public_key_sha256 ? -1 : 1;
  const left = a.signer ?? "";
  const right = b.signer ?? "";
  return left < right ? -1 : left > right ? 1 : 0;
}

function materialFromValidation(validation) {
  return {
    protocol: RELEASE_KEY_TRUST_POLICY_MATERIAL_PROTOCOL,
    policy_protocol: RELEASE_KEY_TRUST_POLICY_PROTOCOL,
    policy_id: validation.policy_id,
    trusted_keys: validation.trusted_keys.map(entry => ({ ...entry })).sort(compareEntries)
  };
}

export function validateReleaseKeyTrustPolicy(policy) {
  try {
    if (!policy || policy.protocol !== RELEASE_KEY_TRUST_POLICY_PROTOCOL) return { valid: false, reason: "invalid_policy_protocol" };
    if (!Array.isArray(policy.trusted_keys) || policy.trusted_keys.length === 0) return { valid: false, reason: "empty_trusted_keys" };
    const normalized = policy.trusted_keys.map(normalizeEntry);
    const fingerprints = normalized.map(entry => entry.public_key_sha256);
    if (new Set(fingerprints).size !== fingerprints.length) return { valid: false, reason: "duplicate_trusted_key" };
    if (policy.policy_id !== undefined && policy.policy_id !== null && typeof policy.policy_id !== "string") return { valid: false, reason: "invalid_policy_id" };
    return {
      valid: true,
      reason: null,
      policy_id: policy.policy_id ?? null,
      trusted_keys: normalized
    };
  } catch {
    return { valid: false, reason: "invalid_policy_structure" };
  }
}

export function releaseKeyTrustPolicyFingerprint(policy) {
  const validation = validateReleaseKeyTrustPolicy(policy);
  if (!validation.valid) throw new TypeError(`invalid release-key trust policy: ${validation.reason}`);
  const material = canonicalJSONStringify(materialFromValidation(validation));
  return crypto.createHash("sha256").update(Buffer.from(material, "utf8")).digest("hex");
}

export function verifyTrustedSemanticReleaseProof(proof, policy, { expected_policy_sha256 = null } = {}) {
  const base = {
    verified: false,
    semantic_proof_valid: false,
    trust_policy_valid: false,
    release_key_trusted: false,
    signer_constraint_valid: false,
    policy_fingerprint_valid: expected_policy_sha256 === null ? null : false,
    policy_id: null,
    policy_sha256: null,
    signer: null,
    public_key_sha256: null,
    release_id: null,
    reason: null
  };

  const semantic = verifySemanticReleaseProof(proof);
  if (!semantic.verified) return { ...base, reason: "invalid_semantic_release_proof" };

  const trust = validateReleaseKeyTrustPolicy(policy);
  if (!trust.valid) {
    return {
      ...base,
      semantic_proof_valid: true,
      public_key_sha256: proof.public_key_sha256 ?? null,
      release_id: proof.release_id ?? null,
      reason: trust.reason
    };
  }

  const policySha256 = releaseKeyTrustPolicyFingerprint(policy);
  if (expected_policy_sha256 !== null) {
    if (!validHash(expected_policy_sha256)) {
      return {
        ...base,
        semantic_proof_valid: true,
        trust_policy_valid: true,
        policy_id: trust.policy_id,
        policy_sha256: policySha256,
        public_key_sha256: proof.public_key_sha256 ?? null,
        release_id: proof.release_id ?? null,
        reason: "invalid_expected_policy_sha256"
      };
    }
    if (policySha256 !== expected_policy_sha256) {
      return {
        ...base,
        semantic_proof_valid: true,
        trust_policy_valid: true,
        policy_id: trust.policy_id,
        policy_sha256: policySha256,
        public_key_sha256: proof.public_key_sha256 ?? null,
        release_id: proof.release_id ?? null,
        reason: "trust_policy_fingerprint_mismatch"
      };
    }
  }

  const candidates = trust.trusted_keys.filter(entry => entry.public_key_sha256 === proof.public_key_sha256);
  if (!candidates.length) {
    return {
      ...base,
      semantic_proof_valid: true,
      trust_policy_valid: true,
      policy_fingerprint_valid: expected_policy_sha256 === null ? null : true,
      policy_id: trust.policy_id,
      policy_sha256: policySha256,
      public_key_sha256: proof.public_key_sha256,
      release_id: proof.release_id ?? null,
      reason: "release_key_not_trusted"
    };
  }

  const signerMatch = candidates.some(entry => entry.signer === null || entry.signer === semantic.signer);
  if (!signerMatch) {
    return {
      ...base,
      semantic_proof_valid: true,
      trust_policy_valid: true,
      release_key_trusted: true,
      policy_fingerprint_valid: expected_policy_sha256 === null ? null : true,
      policy_id: trust.policy_id,
      policy_sha256: policySha256,
      public_key_sha256: proof.public_key_sha256,
      release_id: proof.release_id ?? null,
      reason: "signer_constraint_mismatch"
    };
  }

  return {
    ...base,
    verified: true,
    semantic_proof_valid: true,
    trust_policy_valid: true,
    release_key_trusted: true,
    signer_constraint_valid: true,
    policy_fingerprint_valid: expected_policy_sha256 === null ? null : true,
    policy_id: trust.policy_id,
    policy_sha256: policySha256,
    signer: semantic.signer,
    public_key_sha256: proof.public_key_sha256,
    release_id: proof.release_id ?? null,
    reason: null
  };
}
