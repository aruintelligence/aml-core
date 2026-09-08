// runtime/auditAttestation.js
// ĀML v1.3 — Ed25519 attestations for runtime audit-stream heads.

import crypto from "node:crypto";
import { verifyAuditStream } from "./auditStream.js";

function sha256(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

export function signAuditCheckpoint(stream, privateKeyPem, options = {}) {
  const verification = verifyAuditStream(stream);
  if (!verification.verified) throw new Error("Cannot sign an invalid ĀML audit stream.");

  const checkpoint = {
    protocol: "ĀML Runtime Audit Checkpoint",
    version: "1.0",
    stream_id: stream.stream_id,
    entries: verification.entries,
    head_hash: verification.head_hash,
    checkpointed_at: options.timestamp ?? new Date().toISOString()
  };

  const payload = Buffer.from(JSON.stringify(checkpoint));
  const privateKey = crypto.createPrivateKey(privateKeyPem);
  const publicKey = crypto.createPublicKey(privateKey);
  const publicPem = publicKey.export({ type: "spki", format: "pem" }).toString();
  const publicDer = publicKey.export({ type: "spki", format: "der" });

  return {
    ...checkpoint,
    attestation: {
      algorithm: "Ed25519",
      signer: options.signer || null,
      public_key_sha256: sha256(publicDer),
      public_key_pem: publicPem,
      signature_base64: crypto.sign(null, payload, privateKey).toString("base64")
    }
  };
}

export function verifyAuditCheckpoint(stream, signedCheckpoint) {
  const verification = verifyAuditStream(stream);
  if (!signedCheckpoint?.attestation) throw new Error("Audit checkpoint attestation is missing.");

  const { attestation, ...checkpoint } = signedCheckpoint;
  const publicKey = crypto.createPublicKey(attestation.public_key_pem);
  const publicDer = publicKey.export({ type: "spki", format: "der" });
  const payload = Buffer.from(JSON.stringify(checkpoint));
  const signature = Buffer.from(attestation.signature_base64, "base64");

  const signatureValid = crypto.verify(null, payload, publicKey, signature);
  const fingerprintValid = sha256(publicDer) === attestation.public_key_sha256;
  const streamMatch = verification.verified &&
    checkpoint.stream_id === stream.stream_id &&
    checkpoint.entries === verification.entries &&
    checkpoint.head_hash === verification.head_hash;

  return {
    verified: signatureValid && fingerprintValid && streamMatch,
    signature_valid: signatureValid,
    public_key_fingerprint_valid: fingerprintValid,
    stream_match: streamMatch,
    head_hash: verification.head_hash,
    signer: attestation.signer || null
  };
}
