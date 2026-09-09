import crypto from "node:crypto";
import { canonicalJSONStringify } from "../protocol/canonicalJson.js";

function sha256(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function keyFingerprint(publicKey) {
  return sha256(publicKey.export({ type: "spki", format: "der" }));
}

function validDate(value) {
  return typeof value === "string" && Number.isFinite(Date.parse(value));
}

// Legacy integrity-only constructor. This proves object consistency, not issuer authority.
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

export function createSignedTrustDelegation(
  { issuer, delegate, delegate_public_key_pem, capabilities = [], issued_at = null, expires_at = null } = {},
  issuerPrivateKeyPem
) {
  if (!issuer || !delegate) throw new Error("issuer and delegate are required");
  if (!issuerPrivateKeyPem) throw new Error("issuer private key is required");
  if (!delegate_public_key_pem) throw new Error("delegate public key is required");

  const issuerPrivateKey = crypto.createPrivateKey(issuerPrivateKeyPem);
  const issuerPublicKey = crypto.createPublicKey(issuerPrivateKey);
  const delegatePublicKey = crypto.createPublicKey(delegate_public_key_pem);
  const body = {
    type: "aml-trust-delegation/2",
    issuer,
    issuer_key_fingerprint: keyFingerprint(issuerPublicKey),
    delegate,
    delegate_key_fingerprint: keyFingerprint(delegatePublicKey),
    capabilities: [...new Set(capabilities)].sort(),
    issued_at,
    expires_at
  };
  const canonical = canonicalJSONStringify(body);

  return {
    ...body,
    delegation_hash: sha256(canonical),
    issuer_public_key_pem: issuerPublicKey.export({ type: "spki", format: "pem" }).toString(),
    signature_base64: crypto.sign(null, Buffer.from(canonical), issuerPrivateKey).toString("base64")
  };
}

export function verifyTrustDelegation(delegation, { now = null, requiredCapability = null } = {}) {
  if (!delegation || !["aml-trust-delegation/1", "aml-trust-delegation/2"].includes(delegation.type)) {
    return { valid: false, reason: "invalid_type", authority_authenticated: false };
  }

  if (delegation.expires_at !== null && delegation.expires_at !== undefined && !validDate(delegation.expires_at)) {
    return { valid: false, reason: "invalid_expiry", authority_authenticated: false };
  }
  if (delegation.issued_at !== null && delegation.issued_at !== undefined && !validDate(delegation.issued_at)) {
    return { valid: false, reason: "invalid_issued_at", authority_authenticated: false };
  }
  if (now !== null && now !== undefined && !validDate(now)) {
    return { valid: false, reason: "invalid_now", authority_authenticated: false };
  }

  if (delegation.type === "aml-trust-delegation/1") {
    const { delegation_hash, ...body } = delegation;
    if (sha256(canonicalJSONStringify(body)) !== delegation_hash) {
      return { valid: false, reason: "hash_mismatch", authority_authenticated: false };
    }
    if (now && delegation.expires_at && new Date(now) >= new Date(delegation.expires_at)) {
      return { valid: false, reason: "expired", authority_authenticated: false };
    }
    if (requiredCapability && !delegation.capabilities.includes(requiredCapability)) {
      return { valid: false, reason: "capability_not_delegated", authority_authenticated: false };
    }
    return {
      valid: true,
      reason: null,
      delegation_hash,
      authority_authenticated: false,
      integrity_only: true
    };
  }

  const {
    delegation_hash,
    issuer_public_key_pem,
    signature_base64,
    ...body
  } = delegation;
  const canonical = canonicalJSONStringify(body);
  if (sha256(canonical) !== delegation_hash) {
    return { valid: false, reason: "hash_mismatch", authority_authenticated: false };
  }

  try {
    const issuerPublicKey = crypto.createPublicKey(issuer_public_key_pem);
    if (keyFingerprint(issuerPublicKey) !== delegation.issuer_key_fingerprint) {
      return { valid: false, reason: "issuer_key_fingerprint_mismatch", authority_authenticated: false };
    }
    const signatureValid = crypto.verify(
      null,
      Buffer.from(canonical),
      issuerPublicKey,
      Buffer.from(signature_base64, "base64")
    );
    if (!signatureValid) return { valid: false, reason: "signature_invalid", authority_authenticated: false };
  } catch {
    return { valid: false, reason: "signature_invalid", authority_authenticated: false };
  }

  if (now && delegation.expires_at && new Date(now) >= new Date(delegation.expires_at)) {
    return { valid: false, reason: "expired", authority_authenticated: true };
  }
  if (requiredCapability && !delegation.capabilities.includes(requiredCapability)) {
    return { valid: false, reason: "capability_not_delegated", authority_authenticated: true };
  }

  return {
    valid: true,
    reason: null,
    delegation_hash,
    authority_authenticated: true,
    issuer_key_fingerprint: delegation.issuer_key_fingerprint,
    delegate_key_fingerprint: delegation.delegate_key_fingerprint
  };
}

export function verifyDelegationChain(
  chain,
  { rootIssuer = null, rootKeyFingerprint = null, now = null, requiredCapability = null, integrityOnly = false } = {}
) {
  if (!Array.isArray(chain) || chain.length === 0) return { valid: false, reason: "empty_chain" };

  if (integrityOnly) {
    for (let i = 0; i < chain.length; i += 1) {
      const result = verifyTrustDelegation(chain[i], { now, requiredCapability });
      if (!result.valid) return { valid: false, reason: result.reason, index: i, authority_authenticated: false };
      if (i > 0 && chain[i - 1].delegate !== chain[i].issuer) {
        return { valid: false, reason: "broken_chain", index: i, authority_authenticated: false };
      }
    }
    if (rootIssuer && chain[0].issuer !== rootIssuer) {
      return { valid: false, reason: "unexpected_root", authority_authenticated: false };
    }
    return { valid: true, reason: null, leaf: chain.at(-1).delegate, authority_authenticated: false, integrity_only: true };
  }

  if (!rootKeyFingerprint) return { valid: false, reason: "root_key_required", authority_authenticated: false };

  for (let i = 0; i < chain.length; i += 1) {
    const result = verifyTrustDelegation(chain[i], { now, requiredCapability });
    if (!result.valid) return { valid: false, reason: result.reason, index: i, authority_authenticated: false };
    if (!result.authority_authenticated) {
      return { valid: false, reason: "unauthenticated_delegation", index: i, authority_authenticated: false };
    }
    if (i === 0 && chain[i].issuer_key_fingerprint !== rootKeyFingerprint) {
      return { valid: false, reason: "unexpected_root_key", index: i, authority_authenticated: false };
    }
    if (i > 0) {
      if (chain[i - 1].delegate !== chain[i].issuer) {
        return { valid: false, reason: "broken_chain", index: i, authority_authenticated: false };
      }
      if (chain[i - 1].delegate_key_fingerprint !== chain[i].issuer_key_fingerprint) {
        return { valid: false, reason: "broken_key_continuity", index: i, authority_authenticated: false };
      }
    }
  }

  if (rootIssuer && chain[0].issuer !== rootIssuer) {
    return { valid: false, reason: "unexpected_root", authority_authenticated: false };
  }

  return {
    valid: true,
    reason: null,
    leaf: chain.at(-1).delegate,
    leaf_key_fingerprint: chain.at(-1).delegate_key_fingerprint,
    authority_authenticated: true
  };
}
