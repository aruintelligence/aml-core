// runtime/policyPack.js
// ĀML v1.3 — signed, data-only policy packs.

import crypto from "node:crypto";
import { resolvePolicy } from "./policyEngine.js";

function stableStringify(value) {
  if (Array.isArray(value)) return `[${value.map(stableStringify).join(",")}]`;
  if (value && typeof value === "object") {
    return `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${stableStringify(value[key])}`).join(",")}}`;
  }
  return JSON.stringify(value);
}

function sha256(value) {
  return crypto.createHash("sha256").update(typeof value === "string" ? value : stableStringify(value)).digest("hex");
}

export function normalizePolicyPack(pack) {
  if (!pack || typeof pack !== "object" || Array.isArray(pack)) throw new TypeError("ĀML policy pack must be an object.");
  if (!pack.id || typeof pack.id !== "string") throw new Error("Policy pack id is required.");
  if (!Array.isArray(pack.policies) || pack.policies.length === 0) throw new Error("Policy pack policies must be a non-empty array.");

  // v1.3 policy packs are intentionally data-only: they may reference installed
  // policy IDs but cannot embed executable JavaScript.
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
  const payload = Buffer.from(stableStringify(normalized));
  const privateKey = crypto.createPrivateKey(privateKeyPem);
  const publicKey = crypto.createPublicKey(privateKey);
  const publicDer = publicKey.export({ type: "spki", format: "der" });
  const publicPem = publicKey.export({ type: "spki", format: "pem" }).toString();
  const signature = crypto.sign(null, payload, privateKey);

  return {
    ...normalized,
    pack_sha256: sha256(normalized),
    attestation: {
      algorithm: "Ed25519",
      signer: options.signer || normalized.issuer || null,
      signed_at: options.timestamp ?? new Date().toISOString(),
      public_key_sha256: sha256(publicDer),
      public_key_pem: publicPem,
      signature_base64: signature.toString("base64")
    }
  };
}

export function verifySignedPolicyPack(signedPack) {
  if (!signedPack || signedPack.protocol !== "ĀML Policy Pack") throw new Error("Invalid ĀML policy pack.");
  if (!signedPack.attestation) throw new Error("Signed policy pack attestation is missing.");

  const { pack_sha256, attestation, ...packFields } = signedPack;
  const normalized = normalizePolicyPack(packFields);
  const payload = Buffer.from(stableStringify(normalized));
  const publicKey = crypto.createPublicKey(attestation.public_key_pem);
  const publicDer = publicKey.export({ type: "spki", format: "der" });
  const expectedPackHash = sha256(normalized);
  const signature = Buffer.from(attestation.signature_base64, "base64");
  const signatureValid = crypto.verify(null, payload, publicKey, signature);
  const fingerprintValid = sha256(publicDer) === attestation.public_key_sha256;
  const hashValid = expectedPackHash === pack_sha256;

  return {
    verified: signatureValid && fingerprintValid && hashValid,
    signature_valid: signatureValid,
    public_key_fingerprint_valid: fingerprintValid,
    pack_hash_valid: hashValid,
    pack_sha256: expectedPackHash,
    signer: attestation.signer || null,
    signed_at: attestation.signed_at || null
  };
}
