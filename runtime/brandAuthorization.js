import crypto from "node:crypto";
import { canonicalJSONStringify } from "../protocol/canonicalJson.js";
import { isRevoked } from "./revocationRegistry.js";

function sha256(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

export function signBrandAuthorization({ grantee, marks = [], uses = [], issued_at = null, expires_at = null, authorization_id = null, agreement_reference = null } = {}, privateKeyPem, options = {}) {
  if (!grantee) throw new Error("grantee is required");
  if (!Array.isArray(marks) || marks.length === 0) throw new Error("at least one mark is required");
  if (!privateKeyPem) throw new Error("private key is required");

  const body = {
    type: "aml-brand-authorization/1",
    issuer: options.issuer ?? "ĀRU Intelligence Inc.",
    grantee,
    authorization_id: authorization_id ?? crypto.randomUUID(),
    marks: [...new Set(marks)].sort(),
    permitted_uses: [...new Set(uses)].sort(),
    issued_at,
    expires_at,
    agreement_reference
  };

  const privateKey = crypto.createPrivateKey(privateKeyPem);
  const publicKey = crypto.createPublicKey(privateKey);
  const publicKeyPem = publicKey.export({ type: "spki", format: "pem" }).toString();
  const canonical = canonicalJSONStringify(body);
  const credentialHash = sha256(canonical);
  const signature = crypto.sign(null, Buffer.from(canonical), privateKey);

  return {
    ...body,
    credential_hash: credentialHash,
    algorithm: "Ed25519",
    public_key_pem: publicKeyPem,
    public_key_sha256: sha256(publicKey.export({ type: "spki", format: "der" })),
    signature_base64: signature.toString("base64")
  };
}

export function verifyBrandAuthorization(credential, { now = null, revocation_registry = null, expected_issuer = null } = {}) {
  if (!credential || credential.type !== "aml-brand-authorization/1") return { valid: false, reason: "invalid_type" };
  const {
    credential_hash,
    algorithm,
    public_key_pem,
    public_key_sha256,
    signature_base64,
    ...body
  } = credential;

  if (algorithm !== "Ed25519") return { valid: false, reason: "unsupported_algorithm" };
  if (expected_issuer && credential.issuer !== expected_issuer) return { valid: false, reason: "issuer_mismatch" };
  if (now && credential.expires_at && new Date(now) >= new Date(credential.expires_at)) return { valid: false, reason: "expired" };

  const canonical = canonicalJSONStringify(body);
  if (sha256(canonical) !== credential_hash) return { valid: false, reason: "hash_mismatch" };

  try {
    const publicKey = crypto.createPublicKey(public_key_pem);
    const fingerprint = sha256(publicKey.export({ type: "spki", format: "der" }));
    if (fingerprint !== public_key_sha256) return { valid: false, reason: "public_key_fingerprint_mismatch" };
    const signatureValid = crypto.verify(null, Buffer.from(canonical), publicKey, Buffer.from(signature_base64, "base64"));
    if (!signatureValid) return { valid: false, reason: "signature_invalid" };
  } catch {
    return { valid: false, reason: "invalid_key_or_signature" };
  }

  if (revocation_registry) {
    const revocation = isRevoked(revocation_registry, credential_hash);
    if (!revocation.registry_valid) return { valid: false, reason: "invalid_revocation_registry" };
    if (revocation.revoked) return { valid: false, reason: "revoked", revocation: revocation.entry };
  }

  return {
    valid: true,
    reason: null,
    issuer: credential.issuer,
    grantee: credential.grantee,
    marks: credential.marks,
    permitted_uses: credential.permitted_uses,
    credential_hash
  };
}
