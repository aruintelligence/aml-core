import crypto from "node:crypto";

import { canonicalJSONStringify } from "../protocol/canonicalJson.js";
import { verifyMeaningManifestIntegrity } from "./meaningManifest.js";

const ATTESTATION_PROTOCOL = "aml-meaning-manifest-attestation/1";
const ATTESTATION_VERSION = "1.0";
const ALGORITHM = "Ed25519";

function sha256(content) {
  return crypto.createHash("sha256").update(content).digest("hex");
}

function signedMaterial(attestation) {
  return {
    protocol: ATTESTATION_PROTOCOL,
    version: ATTESTATION_VERSION,
    algorithm: ALGORITHM,
    manifest_protocol: attestation.manifest_protocol,
    manifest_version: attestation.manifest_version,
    manifest_material_protocol: attestation.manifest_material_protocol,
    fingerprint_protocol: attestation.fingerprint_protocol,
    manifest_root_sha256: attestation.manifest_root_sha256,
    file_count: attestation.file_count,
    signer: attestation.signer ?? null,
    signed_at: attestation.signed_at
  };
}

function publicKeyFingerprint(publicKey) {
  return sha256(publicKey.export({ type: "spki", format: "der" }));
}

function validTimestamp(value) {
  return typeof value === "string" && value.length > 0 && Number.isFinite(Date.parse(value));
}

function validSignatureEncoding(value) {
  return typeof value === "string" && value.length > 0 && /^[A-Za-z0-9+/]+={0,2}$/.test(value) && value.length % 4 === 0;
}

export function signMeaningManifest(manifest, privateKeyPem, options = {}) {
  const integrity = verifyMeaningManifestIntegrity(manifest);
  if (!integrity.verified) {
    throw new Error(`Cannot sign invalid Meaning Manifest: ${integrity.reason}`);
  }

  const privateKey = crypto.createPrivateKey(privateKeyPem);
  if (privateKey.asymmetricKeyType !== "ed25519") {
    throw new TypeError("Meaning Manifest attestation requires an Ed25519 private key.");
  }
  const publicKey = crypto.createPublicKey(privateKey);
  const publicKeyPem = publicKey.export({ type: "spki", format: "pem" }).toString();
  const signedAt = options.timestamp ?? new Date().toISOString();
  if (!validTimestamp(signedAt)) throw new TypeError("Meaning Manifest signed_at must be an ISO-compatible timestamp.");

  const attestation = {
    protocol: ATTESTATION_PROTOCOL,
    version: ATTESTATION_VERSION,
    algorithm: ALGORITHM,
    manifest_protocol: manifest.protocol,
    manifest_version: manifest.version,
    manifest_material_protocol: manifest.material_protocol,
    fingerprint_protocol: manifest.fingerprint_protocol,
    manifest_root_sha256: manifest.root_sha256,
    file_count: manifest.file_count,
    signer: options.signer ?? null,
    signed_at: signedAt,
    public_key_sha256: publicKeyFingerprint(publicKey),
    public_key_pem: publicKeyPem
  };

  const bytes = Buffer.from(canonicalJSONStringify(signedMaterial(attestation)), "utf8");
  const signature = crypto.sign(null, bytes, privateKey);
  return { ...attestation, signature_base64: signature.toString("base64") };
}

export function verifySignedMeaningManifest(attestation, manifest) {
  const manifestIntegrity = verifyMeaningManifestIntegrity(manifest);
  const base = {
    verified: false,
    manifest_integrity_valid: manifestIntegrity.verified,
    manifest_binding_valid: false,
    signature_valid: false,
    public_key_fingerprint_valid: false,
    attribution_bound: false,
    signer: null,
    signed_at: null,
    claimed_signer: attestation?.signer ?? null,
    claimed_signed_at: attestation?.signed_at ?? null,
    manifest_root_sha256: manifest?.root_sha256 ?? null
  };

  try {
    if (!manifestIntegrity.verified) return { ...base, reason: manifestIntegrity.reason };
    if (!attestation || attestation.protocol !== ATTESTATION_PROTOCOL || attestation.version !== ATTESTATION_VERSION || attestation.algorithm !== ALGORITHM) {
      return { ...base, reason: "invalid_attestation_contract" };
    }
    if (!validTimestamp(attestation.signed_at)) return { ...base, reason: "invalid_signed_at" };
    if (!validSignatureEncoding(attestation.signature_base64)) return { ...base, reason: "invalid_signature_encoding" };
    if (typeof attestation.public_key_sha256 !== "string" || !/^[a-f0-9]{64}$/.test(attestation.public_key_sha256)) {
      return { ...base, reason: "invalid_public_key_fingerprint" };
    }

    const bindingValid =
      attestation.manifest_protocol === manifest.protocol &&
      attestation.manifest_version === manifest.version &&
      attestation.manifest_material_protocol === manifest.material_protocol &&
      attestation.fingerprint_protocol === manifest.fingerprint_protocol &&
      attestation.manifest_root_sha256 === manifest.root_sha256 &&
      attestation.file_count === manifest.file_count;

    const publicKey = crypto.createPublicKey(attestation.public_key_pem);
    if (publicKey.asymmetricKeyType !== "ed25519") return { ...base, manifest_binding_valid: bindingValid, reason: "unsupported_public_key_type" };
    const fingerprintValid = publicKeyFingerprint(publicKey) === attestation.public_key_sha256;
    const bytes = Buffer.from(canonicalJSONStringify(signedMaterial(attestation)), "utf8");
    const signature = Buffer.from(attestation.signature_base64, "base64");
    const signatureValid = crypto.verify(null, bytes, publicKey, signature);
    const verified = manifestIntegrity.verified && bindingValid && fingerprintValid && signatureValid;

    return {
      ...base,
      verified,
      reason: verified ? null : !bindingValid ? "manifest_binding_mismatch" : !fingerprintValid ? "public_key_fingerprint_mismatch" : "signature_invalid",
      manifest_binding_valid: bindingValid,
      signature_valid: signatureValid,
      public_key_fingerprint_valid: fingerprintValid,
      attribution_bound: verified,
      signer: verified ? attestation.signer ?? null : null,
      signed_at: verified ? attestation.signed_at : null
    };
  } catch {
    return { ...base, reason: "attestation_verification_error" };
  }
}
