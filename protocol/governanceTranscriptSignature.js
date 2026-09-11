import crypto from "node:crypto";
import { canonicalJSONStringify } from "./canonicalJson.js";
import { verifyGovernanceStreamTranscript, AML_GOVERNANCE_TRANSCRIPT } from "./governanceTranscript.js";

export const AML_SIGNED_GOVERNANCE_TRANSCRIPT = "aml-signed-governance-stream-transcript/1";
export const AML_SIGNED_GOVERNANCE_TRANSCRIPT_VERIFICATION = "aml-signed-governance-stream-transcript-verification/1";

function transcriptMaterial(transcript) {
  if (!transcript || transcript.protocol !== AML_GOVERNANCE_TRANSCRIPT) {
    throw new Error("a valid aml-governance-stream-transcript/1 object is required");
  }
  return Buffer.from(canonicalJSONStringify(transcript), "utf8");
}

function publicKeyFingerprint(publicKeyPem) {
  const key = crypto.createPublicKey(publicKeyPem);
  const der = key.export({ type: "spki", format: "der" });
  return crypto.createHash("sha256").update(der).digest("hex");
}

export function signGovernanceStreamTranscript(transcript, privateKeyPem, options = {}) {
  const verification = verifyGovernanceStreamTranscript(transcript);
  if (!verification.valid) {
    throw new Error(`refusing to sign invalid governance transcript: ${verification.errors.join("; ")}`);
  }
  const privateKey = crypto.createPrivateKey(privateKeyPem);
  if (privateKey.asymmetricKeyType !== "ed25519") {
    throw new Error("governance transcript signing requires an Ed25519 private key");
  }
  const publicKey = crypto.createPublicKey(privateKey);
  const publicKeyPem = publicKey.export({ type: "spki", format: "pem" }).toString();
  const fingerprint = publicKeyFingerprint(publicKeyPem);
  const signature = crypto.sign(null, transcriptMaterial(transcript), privateKey).toString("base64");

  return {
    protocol: AML_SIGNED_GOVERNANCE_TRANSCRIPT,
    transcript: structuredClone(transcript),
    signature: {
      algorithm: "Ed25519",
      key_id: options.key_id || `sha256:${fingerprint}`,
      public_key_fingerprint_sha256: fingerprint,
      public_key_pem: publicKeyPem,
      signature_base64: signature,
      signer: options.signer || null,
      signed_at: options.signed_at || null,
      scope: options.scope || "governance-transcript-integrity"
    }
  };
}

export function verifySignedGovernanceStreamTranscript(signed, options = {}) {
  const errors = [];
  if (!signed || typeof signed !== "object" || signed.protocol !== AML_SIGNED_GOVERNANCE_TRANSCRIPT) {
    return {
      protocol: AML_SIGNED_GOVERNANCE_TRANSCRIPT_VERIFICATION,
      valid: false,
      transcript_valid: false,
      signature_valid: false,
      trusted_key: false,
      errors: ["unsupported signed transcript protocol"]
    };
  }

  const transcriptVerification = verifyGovernanceStreamTranscript(signed.transcript);
  if (!transcriptVerification.valid) errors.push("embedded governance transcript is invalid");

  const signature = signed.signature || {};
  let signatureValid = false;
  let fingerprint = null;
  try {
    if (signature.algorithm !== "Ed25519") throw new Error("signature algorithm must be Ed25519");
    fingerprint = publicKeyFingerprint(signature.public_key_pem);
    if (fingerprint !== signature.public_key_fingerprint_sha256) {
      throw new Error("public key fingerprint mismatch");
    }
    signatureValid = crypto.verify(
      null,
      transcriptMaterial(signed.transcript),
      crypto.createPublicKey(signature.public_key_pem),
      Buffer.from(signature.signature_base64, "base64")
    );
    if (!signatureValid) errors.push("Ed25519 signature verification failed");
  } catch (error) {
    errors.push(error.message || String(error));
  }

  const trustedFingerprints = new Set(options.trusted_fingerprints || []);
  const trustedKey = fingerprint != null && trustedFingerprints.has(fingerprint);
  if (options.require_trusted_key === true && !trustedKey) {
    errors.push("signing key is not in the supplied trust set");
  }

  if (options.expected_key_id && signature.key_id !== options.expected_key_id) {
    errors.push("unexpected signing key id");
  }

  return {
    protocol: AML_SIGNED_GOVERNANCE_TRANSCRIPT_VERIFICATION,
    valid: transcriptVerification.valid && signatureValid && errors.length === 0,
    transcript_valid: transcriptVerification.valid,
    hash_chain_valid: transcriptVerification.hash_chain_valid,
    replay_valid: transcriptVerification.replay_valid,
    signature_valid: signatureValid,
    trusted_key: trustedKey,
    key_id: signature.key_id || null,
    public_key_fingerprint_sha256: fingerprint,
    signer: signature.signer || null,
    scope: signature.scope || null,
    errors
  };
}
