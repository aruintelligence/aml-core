// compiler/signature.js
// Detached Ed25519 attestations for ĀML build manifests.

import crypto from "node:crypto";
import fs from "node:fs";

function sha256(content) {
  return crypto.createHash("sha256").update(content).digest("hex");
}

export function signBuildManifest(manifestPath, privateKeyPem, options = {}) {
  const manifest = fs.readFileSync(manifestPath);
  const privateKey = crypto.createPrivateKey(privateKeyPem);
  const publicKey = crypto.createPublicKey(privateKey);
  const publicKeyPem = publicKey.export({ type: "spki", format: "pem" }).toString();
  const signature = crypto.sign(null, manifest, privateKey);

  return {
    protocol: "ĀML Build Attestation",
    version: "1.0",
    algorithm: "Ed25519",
    manifest_path: manifestPath,
    manifest_sha256: sha256(manifest),
    public_key_sha256: sha256(publicKey.export({ type: "spki", format: "der" })),
    public_key_pem: publicKeyPem,
    signature_base64: signature.toString("base64"),
    signed_at: options.timestamp ?? new Date().toISOString(),
    signer: options.signer ?? null
  };
}

export function verifyBuildAttestation(attestation, manifestPath = attestation?.manifest_path) {
  if (!attestation || attestation.protocol !== "ĀML Build Attestation") {
    throw new Error("Invalid ĀML build attestation.");
  }
  if (!manifestPath) throw new Error("Manifest path is required.");

  const manifest = fs.readFileSync(manifestPath);
  const actualHash = sha256(manifest);
  const publicKey = crypto.createPublicKey(attestation.public_key_pem);
  const signature = Buffer.from(attestation.signature_base64, "base64");
  const signatureValid = crypto.verify(null, manifest, publicKey, signature);
  const hashValid = actualHash === attestation.manifest_sha256;
  const publicKeyFingerprint = sha256(publicKey.export({ type: "spki", format: "der" }));

  return {
    verified: hashValid && signatureValid && publicKeyFingerprint === attestation.public_key_sha256,
    hash_valid: hashValid,
    signature_valid: signatureValid,
    public_key_fingerprint_valid: publicKeyFingerprint === attestation.public_key_sha256,
    manifest_sha256: actualHash,
    signer: attestation.signer ?? null,
    signed_at: attestation.signed_at ?? null
  };
}
