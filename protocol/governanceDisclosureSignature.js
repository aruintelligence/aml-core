import crypto from "node:crypto";
import { canonicalJSONStringify } from "./canonicalJson.js";
import { verifyGovernanceDisclosure, AML_GOVERNANCE_DISCLOSURE } from "./governanceDisclosure.js";

export const AML_GOVERNANCE_DISCLOSURE_COMMITMENT = "aml-governance-disclosure-commitment/1";
export const AML_SIGNED_GOVERNANCE_DISCLOSURE_COMMITMENT = "aml-signed-governance-disclosure-commitment/1";
export const AML_SIGNED_GOVERNANCE_DISCLOSURE_COMMITMENT_VERIFICATION = "aml-signed-governance-disclosure-commitment-verification/1";

function publicKeyFingerprint(publicKeyPem) {
  const key = crypto.createPublicKey(publicKeyPem);
  const der = key.export({ type: "spki", format: "der" });
  return crypto.createHash("sha256").update(der).digest("hex");
}

function material(commitment) {
  return Buffer.from(canonicalJSONStringify(commitment), "utf8");
}

export function createGovernanceDisclosureCommitment(disclosure) {
  if (!disclosure || disclosure.protocol !== AML_GOVERNANCE_DISCLOSURE) {
    throw new Error("a valid aml-governance-selective-disclosure/1 object is required");
  }
  const verification = verifyGovernanceDisclosure(disclosure);
  if (!verification.valid) throw new Error(`refusing to commit invalid disclosure: ${verification.errors.join("; ")}`);
  return {
    protocol: AML_GOVERNANCE_DISCLOSURE_COMMITMENT,
    source_transcript_root_sha256: disclosure.source_transcript_root_sha256,
    source_entry_count: disclosure.source_entry_count,
    disclosure_merkle_root_sha256: disclosure.disclosure_merkle_root_sha256
  };
}

export function signGovernanceDisclosureCommitment(disclosure, privateKeyPem, options = {}) {
  const commitment = createGovernanceDisclosureCommitment(disclosure);
  const privateKey = crypto.createPrivateKey(privateKeyPem);
  if (privateKey.asymmetricKeyType !== "ed25519") throw new Error("disclosure commitment signing requires an Ed25519 private key");
  const publicKey = crypto.createPublicKey(privateKey);
  const publicKeyPem = publicKey.export({ type: "spki", format: "pem" }).toString();
  const fingerprint = publicKeyFingerprint(publicKeyPem);
  return {
    protocol: AML_SIGNED_GOVERNANCE_DISCLOSURE_COMMITMENT,
    commitment,
    signature: {
      algorithm: "Ed25519",
      key_id: options.key_id || `sha256:${fingerprint}`,
      public_key_fingerprint_sha256: fingerprint,
      public_key_pem: publicKeyPem,
      signature_base64: crypto.sign(null, material(commitment), privateKey).toString("base64"),
      signer: options.signer || null,
      scope: options.scope || "governance-disclosure-commitment",
      signed_at: options.signed_at || null
    }
  };
}

export function verifySignedGovernanceDisclosureCommitment(signed, options = {}) {
  const errors = [];
  if (!signed || signed.protocol !== AML_SIGNED_GOVERNANCE_DISCLOSURE_COMMITMENT) {
    return { protocol: AML_SIGNED_GOVERNANCE_DISCLOSURE_COMMITMENT_VERIFICATION, valid: false, signature_valid: false, trusted_key: false, errors: ["unsupported signed disclosure commitment protocol"] };
  }
  const commitment = signed.commitment || {};
  if (commitment.protocol !== AML_GOVERNANCE_DISCLOSURE_COMMITMENT) errors.push("invalid disclosure commitment protocol");

  const signature = signed.signature || {};
  let fingerprint = null;
  let signatureValid = false;
  try {
    if (signature.algorithm !== "Ed25519") throw new Error("signature algorithm must be Ed25519");
    fingerprint = publicKeyFingerprint(signature.public_key_pem);
    if (fingerprint !== signature.public_key_fingerprint_sha256) throw new Error("public key fingerprint mismatch");
    signatureValid = crypto.verify(null, material(commitment), crypto.createPublicKey(signature.public_key_pem), Buffer.from(signature.signature_base64, "base64"));
    if (!signatureValid) errors.push("Ed25519 signature verification failed");
  } catch (error) {
    errors.push(error.message || String(error));
  }

  const trusted = new Set(options.trusted_fingerprints || []);
  const revoked = new Set(options.revoked_fingerprints || []);
  const trustedKey = fingerprint != null && trusted.has(fingerprint) && !revoked.has(fingerprint);
  if (fingerprint && revoked.has(fingerprint)) errors.push("signing key is revoked by supplied verifier policy");
  if (options.require_trusted_key === true && !trustedKey) errors.push("signing key is not eligible in supplied verifier trust set");
  if (options.required_scope && signature.scope !== options.required_scope) errors.push("signature scope does not satisfy verifier policy");

  return {
    protocol: AML_SIGNED_GOVERNANCE_DISCLOSURE_COMMITMENT_VERIFICATION,
    valid: signatureValid && errors.length === 0,
    signature_valid: signatureValid,
    trusted_key: trustedKey,
    public_key_fingerprint_sha256: fingerprint,
    key_id: signature.key_id || null,
    signer: signature.signer || null,
    scope: signature.scope || null,
    commitment,
    errors
  };
}

export function verifyGovernanceDisclosureAgainstSignedCommitment(disclosure, signed, options = {}) {
  const signature = verifySignedGovernanceDisclosureCommitment(signed, options);
  const commitment = signed?.commitment || {};
  const disclosureVerification = verifyGovernanceDisclosure(disclosure, {
    expected_merkle_root: commitment.disclosure_merkle_root_sha256,
    expected_transcript_root: commitment.source_transcript_root_sha256
  });
  const countMatches = disclosure?.source_entry_count === commitment.source_entry_count;
  const errors = [...signature.errors, ...disclosureVerification.errors];
  if (!countMatches) errors.push("source entry count does not match signed commitment");
  return {
    protocol: "aml-governance-disclosure-signed-verification/1",
    valid: signature.valid && disclosureVerification.valid && countMatches,
    signature_valid: signature.signature_valid,
    trusted_key: signature.trusted_key,
    disclosure_valid: disclosureVerification.valid,
    source_entry_count_match: countMatches,
    errors,
    claim_boundary: "A valid signed commitment authenticates the commitment under the supplied key policy; it does not establish real-world signer identity, independent witnessing, certification, or official ĀRU authorization unless those properties are separately established."
  };
}
