// runtime/policyPack.js
// ĀML v1.3 — signed, data-only policy packs.

import crypto from "node:crypto";
import { resolvePolicy } from "./policyEngine.js";

function stableStringify(value) {
  if (Array.isArray(value)) return `[${value.map(stableStringify).join(",")}]`;
  if (value && typeof value === "object") {
    return `{${Object.keys(value).sort().filter(key => value[key] !== undefined).map(key => `${JSON.stringify(key)}:${stableStringify(value[key])}`).join(",")}}`;
  }
  return JSON.stringify(value);
}

function sha256(value) {
  return crypto.createHash("sha256").update(typeof value === "string" ? value : stableStringify(value)).digest("hex");
}

function sha256Bytes(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function policyPackAttestationMaterial(packSha256, attestation) {
  return {
    protocol: "ĀML Policy Pack Attestation",
    version: "1.1",
    algorithm: "Ed25519",
    pack_sha256: packSha256,
    signer: attestation.signer ?? null,
    signed_at: attestation.signed_at
  };
}

export function normalizePolicyPack(pack) {
  if (!pack || typeof pack !== "object" || Array.isArray(pack)) throw new TypeError("ĀML policy pack must be an object.");
  if (pack.protocol !== undefined && pack.protocol !== "ĀML Policy Pack") throw new Error("Unsupported policy pack protocol.");
  if (pack.version !== undefined && pack.version !== "1.0") throw new Error("Unsupported policy pack version.");
  if (!pack.id || typeof pack.id !== "string") throw new Error("Policy pack id is required.");
  if (!Array.isArray(pack.policies) || pack.policies.length === 0) throw new Error("Policy pack policies must be a non-empty array.");
  for (const policyId of pack.policies) {
    if (typeof policyId !== "string") throw new Error("Policy pack policies must contain policy IDs only.");
    resolvePolicy(policyId);
  }
  return {
    protocol: "ĀML Policy Pack",
    version: "1.0",
    id: pack.id,
    issuer: pack.issuer || null,
    description: pack.description || "",
    strategy: pack.strategy || "all_must_allow",
    policies: [...pack.policies],
    metadata: pack.metadata && typeof pack.metadata === "object" ? structuredClone(pack.metadata) : {}
  };
}

export function hashPolicyPack(pack) {
  return sha256(normalizePolicyPack(pack));
}

export function signPolicyPack(pack, privateKeyPem, options = {}) {
  const normalized = normalizePolicyPack(pack);
  const privateKey = crypto.createPrivateKey(privateKeyPem);
  const publicKey = crypto.createPublicKey(privateKey);
  const publicDer = publicKey.export({ type: "spki", format: "der" });
  const publicPem = publicKey.export({ type: "spki", format: "pem" }).toString();
  const packSha256 = sha256(normalized);
  const attestation = {
    protocol: "ĀML Policy Pack Attestation",
    version: "1.1",
    algorithm: "Ed25519",
    signer: options.signer ?? normalized.issuer ?? null,
    signed_at: options.timestamp ?? new Date().toISOString(),
    public_key_sha256: sha256Bytes(publicDer),
    public_key_pem: publicPem
  };
  const signature = crypto.sign(null, Buffer.from(stableStringify(policyPackAttestationMaterial(packSha256, attestation)), "utf8"), privateKey);
  return { ...normalized, pack_sha256: packSha256, attestation: { ...attestation, signature_base64: signature.toString("base64") } };
}

export function verifySignedPolicyPack(signedPack) {
  if (!signedPack || signedPack.protocol !== "ĀML Policy Pack") throw new Error("Invalid ĀML policy pack.");
  if (signedPack.version !== "1.0") {
    return { verified: false, signature_valid: false, public_key_fingerprint_valid: false, pack_hash_valid: false, pack_sha256: null, attribution_bound: false, signer: null, signed_at: null, reason: "unsupported policy pack version" };
  }
  if (!signedPack.attestation) throw new Error("Signed policy pack attestation is missing.");

  const { pack_sha256, attestation, ...packFields } = signedPack;
  let normalized;
  try {
    normalized = normalizePolicyPack(packFields);
  } catch (error) {
    return { verified: false, signature_valid: false, public_key_fingerprint_valid: false, pack_hash_valid: false, pack_sha256: null, attribution_bound: false, signer: null, signed_at: null, claimed_signer: attestation.signer ?? null, claimed_signed_at: attestation.signed_at ?? null, reason: error.message };
  }

  const expectedPackHash = sha256(normalized);
  const hashValid = expectedPackHash === pack_sha256;
  const current = attestation.protocol === "ĀML Policy Pack Attestation" && attestation.version === "1.1" && attestation.algorithm === "Ed25519";
  const legacy = attestation.protocol === undefined && attestation.version === undefined && attestation.algorithm === "Ed25519";
  if (!current && !legacy) {
    return { verified: false, signature_valid: false, public_key_fingerprint_valid: false, pack_hash_valid: hashValid, pack_sha256: expectedPackHash, attribution_bound: false, signer: null, signed_at: null, claimed_signer: attestation.signer ?? null, claimed_signed_at: attestation.signed_at ?? null, reason: "unsupported policy pack attestation version" };
  }

  try {
    const publicKey = crypto.createPublicKey(attestation.public_key_pem);
    const publicDer = publicKey.export({ type: "spki", format: "der" });
    const expectedFingerprint = current ? sha256Bytes(publicDer) : sha256(publicDer);
    const publicKeyFingerprintValid = expectedFingerprint === attestation.public_key_sha256;
    const payload = current ? Buffer.from(stableStringify(policyPackAttestationMaterial(expectedPackHash, attestation)), "utf8") : Buffer.from(stableStringify(normalized), "utf8");
    const signatureValid = crypto.verify(null, payload, publicKey, Buffer.from(attestation.signature_base64, "base64"));
    const verified = signatureValid && publicKeyFingerprintValid && hashValid;
    return {
      verified,
      signature_valid: signatureValid,
      public_key_fingerprint_valid: publicKeyFingerprintValid,
      pack_hash_valid: hashValid,
      pack_sha256: expectedPackHash,
      attribution_bound: current && verified,
      signer: current && verified ? attestation.signer ?? null : null,
      signed_at: current && verified ? attestation.signed_at ?? null : null,
      claimed_signer: attestation.signer ?? null,
      claimed_signed_at: attestation.signed_at ?? null
    };
  } catch {
    return { verified: false, signature_valid: false, public_key_fingerprint_valid: false, pack_hash_valid: hashValid, pack_sha256: expectedPackHash, attribution_bound: false, signer: null, signed_at: null, claimed_signer: attestation.signer ?? null, claimed_signed_at: attestation.signed_at ?? null, reason: "malformed policy pack signature material" };
  }
}
