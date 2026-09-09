// compiler/signature.js
// Detached Ed25519 attestations for ĀML build manifests.

import crypto from "node:crypto";
import fs from "node:fs";

function sha256(content) {
  return crypto.createHash("sha256").update(content).digest("hex");
}

function currentAttestationMaterial(attestation) {
  return {
    protocol: "ĀML Build Attestation",
    version: "1.1",
    algorithm: "Ed25519",
    manifest_path: attestation.manifest_path,
    manifest_sha256: attestation.manifest_sha256,
    signed_at: attestation.signed_at,
    signer: attestation.signer ?? null
  };
}

function currentSignedBytes(attestation, manifest) {
  return Buffer.concat([
    Buffer.from(JSON.stringify(currentAttestationMaterial(attestation))),
    Buffer.from("\n"),
    manifest
  ]);
}

export function signBuildManifest(manifestPath, privateKeyPem, options = {}) {
  const manifest = fs.readFileSync(manifestPath);
  const privateKey = crypto.createPrivateKey(privateKeyPem);
  const publicKey = crypto.createPublicKey(privateKey);
  const publicKeyPem = publicKey.export({ type: "spki", format: "pem" }).toString();
  const attestation = {
    protocol: "ĀML Build Attestation",
    version: "1.1",
    algorithm: "Ed25519",
    manifest_path: manifestPath,
    manifest_sha256: sha256(manifest),
    public_key_sha256: sha256(publicKey.export({ type: "spki", format: "der" })),
    public_key_pem: publicKeyPem,
    signed_at: options.timestamp ?? new Date().toISOString(),
    signer: options.signer ?? null
  };
  const signature = crypto.sign(null, currentSignedBytes(attestation, manifest), privateKey);

  return {
    ...attestation,
    signature_base64: signature.toString("base64")
  };
}

export function verifyBuildAttestation(attestation, manifestPath = attestation?.manifest_path) {
  if (!attestation || attestation.protocol !== "ĀML Build Attestation") {
    return {
      verified: false,
      hash_valid: false,
      signature_valid: false,
      public_key_fingerprint_valid: false,
      attribution_bound: false,
      manifest_sha256: null,
      signer: null,
      signed_at: null
    };
  }
  if (!manifestPath) {
    return {
      verified: false,
      hash_valid: false,
      signature_valid: false,
      public_key_fingerprint_valid: false,
      attribution_bound: false,
      manifest_sha256: null,
      signer: null,
      signed_at: null
    };
  }

  const current = attestation.version === "1.1" && attestation.algorithm === "Ed25519";
  const legacy = attestation.version === "1.0" && attestation.algorithm === "Ed25519";
  if (!current && !legacy) {
    return {
      verified: false,
      hash_valid: false,
      signature_valid: false,
      public_key_fingerprint_valid: false,
      attribution_bound: false,
      manifest_sha256: null,
      signer: null,
      signed_at: null,
      claimed_signer: attestation.signer ?? null,
      claimed_signed_at: attestation.signed_at ?? null
    };
  }

  let manifest;
  try {
    manifest = fs.readFileSync(manifestPath);
  } catch {
    return {
      verified: false,
      hash_valid: false,
      signature_valid: false,
      public_key_fingerprint_valid: false,
      attribution_bound: false,
      manifest_sha256: null,
      signer: null,
      signed_at: null,
      claimed_signer: attestation.signer ?? null,
      claimed_signed_at: attestation.signed_at ?? null
    };
  }

  const actualHash = sha256(manifest);
  const hashValid = actualHash === attestation.manifest_sha256;

  try {
    const publicKey = crypto.createPublicKey(attestation.public_key_pem);
    const publicKeyFingerprint = sha256(publicKey.export({ type: "spki", format: "der" }));
    const fingerprintValid = publicKeyFingerprint === attestation.public_key_sha256;
    const signedBytes = current ? currentSignedBytes(attestation, manifest) : manifest;
    const signature = Buffer.from(attestation.signature_base64, "base64");
    const signatureValid = crypto.verify(null, signedBytes, publicKey, signature);
    const verified = hashValid && signatureValid && fingerprintValid;

    return {
      verified,
      hash_valid: hashValid,
      signature_valid: signatureValid,
      public_key_fingerprint_valid: fingerprintValid,
      attribution_bound: current && verified,
      manifest_sha256: actualHash,
      signer: current && verified ? attestation.signer ?? null : null,
      signed_at: current && verified ? attestation.signed_at ?? null : null,
      claimed_signer: attestation.signer ?? null,
      claimed_signed_at: attestation.signed_at ?? null
    };
  } catch {
    return {
      verified: false,
      hash_valid: hashValid,
      signature_valid: false,
      public_key_fingerprint_valid: false,
      attribution_bound: false,
      manifest_sha256: actualHash,
      signer: null,
      signed_at: null,
      claimed_signer: attestation.signer ?? null,
      claimed_signed_at: attestation.signed_at ?? null
    };
  }
}
