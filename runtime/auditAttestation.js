// runtime/auditAttestation.js
// ĀML v1.3 — Ed25519 attestations for runtime audit-stream heads.

import crypto from "node:crypto";
import { verifyAuditStream } from "./auditStream.js";

function sha256(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function currentAttestationMaterial(checkpoint, attestation) {
  return {
    protocol: "ĀML Runtime Audit Checkpoint Attestation",
    version: "1.1",
    algorithm: "Ed25519",
    checkpoint,
    signer: attestation.signer ?? null
  };
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

  const privateKey = crypto.createPrivateKey(privateKeyPem);
  const publicKey = crypto.createPublicKey(privateKey);
  const publicPem = publicKey.export({ type: "spki", format: "pem" }).toString();
  const publicDer = publicKey.export({ type: "spki", format: "der" });
  const attestation = {
    protocol: "ĀML Runtime Audit Checkpoint Attestation",
    version: "1.1",
    algorithm: "Ed25519",
    signer: options.signer ?? null,
    public_key_sha256: sha256(publicDer),
    public_key_pem: publicPem
  };
  const payload = Buffer.from(JSON.stringify(currentAttestationMaterial(checkpoint, attestation)));

  return {
    ...checkpoint,
    attestation: {
      ...attestation,
      signature_base64: crypto.sign(null, payload, privateKey).toString("base64")
    }
  };
}

export function verifyAuditCheckpoint(stream, signedCheckpoint) {
  let verification;
  try {
    verification = verifyAuditStream(stream);
  } catch {
    return {
      verified: false,
      signature_valid: false,
      public_key_fingerprint_valid: false,
      stream_match: false,
      attribution_bound: false,
      head_hash: null,
      signer: null
    };
  }

  if (!signedCheckpoint?.attestation) {
    return {
      verified: false,
      signature_valid: false,
      public_key_fingerprint_valid: false,
      stream_match: false,
      attribution_bound: false,
      head_hash: verification.head_hash,
      signer: null
    };
  }

  const { attestation, ...checkpoint } = signedCheckpoint;
  if (checkpoint.protocol !== "ĀML Runtime Audit Checkpoint" || checkpoint.version !== "1.0") {
    return {
      verified: false,
      signature_valid: false,
      public_key_fingerprint_valid: false,
      stream_match: false,
      attribution_bound: false,
      head_hash: verification.head_hash,
      signer: null,
      claimed_signer: attestation.signer ?? null
    };
  }

  const current = attestation.protocol === "ĀML Runtime Audit Checkpoint Attestation" &&
    attestation.version === "1.1" &&
    attestation.algorithm === "Ed25519";
  const legacy = attestation.protocol === undefined &&
    attestation.version === undefined &&
    attestation.algorithm === "Ed25519";

  if (!current && !legacy) {
    return {
      verified: false,
      signature_valid: false,
      public_key_fingerprint_valid: false,
      stream_match: false,
      attribution_bound: false,
      head_hash: verification.head_hash,
      signer: null,
      claimed_signer: attestation.signer ?? null
    };
  }

  const streamMatch = verification.verified &&
    checkpoint.stream_id === stream.stream_id &&
    checkpoint.entries === verification.entries &&
    checkpoint.head_hash === verification.head_hash;

  try {
    const publicKey = crypto.createPublicKey(attestation.public_key_pem);
    const publicDer = publicKey.export({ type: "spki", format: "der" });
    const payload = current
      ? Buffer.from(JSON.stringify(currentAttestationMaterial(checkpoint, attestation)))
      : Buffer.from(JSON.stringify(checkpoint));
    const signature = Buffer.from(attestation.signature_base64, "base64");
    const signatureValid = crypto.verify(null, payload, publicKey, signature);
    const fingerprintValid = sha256(publicDer) === attestation.public_key_sha256;
    const verified = signatureValid && fingerprintValid && streamMatch;

    return {
      verified,
      signature_valid: signatureValid,
      public_key_fingerprint_valid: fingerprintValid,
      stream_match: streamMatch,
      attribution_bound: current && verified,
      head_hash: verification.head_hash,
      signer: current && verified ? attestation.signer ?? null : null,
      claimed_signer: attestation.signer ?? null
    };
  } catch {
    return {
      verified: false,
      signature_valid: false,
      public_key_fingerprint_valid: false,
      stream_match: streamMatch,
      attribution_bound: false,
      head_hash: verification.head_hash,
      signer: null,
      claimed_signer: attestation.signer ?? null
    };
  }
}
