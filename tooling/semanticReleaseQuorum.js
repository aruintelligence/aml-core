import crypto from "node:crypto";
import { canonicalJSONStringify } from "../protocol/canonicalJson.js";
import { verifySemanticReleaseProof } from "../compiler/semanticReleaseProof.js";

export const SEMANTIC_RELEASE_ENDORSEMENT_PROTOCOL = "aml-semantic-release-endorsement/1";
export const SEMANTIC_RELEASE_QUORUM_POLICY_PROTOCOL = "aml-semantic-release-quorum-policy/1";
const ENDORSEMENT_VERSION = "1.0";
const ALGORITHM = "Ed25519";
const MATERIAL_PROTOCOL = "aml-semantic-release-endorsement-material/1";

function sha256(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function validHash(value) {
  return typeof value === "string" && /^[a-f0-9]{64}$/.test(value);
}

function validTimestamp(value) {
  return typeof value === "string" && value.length > 0 && Number.isFinite(Date.parse(value));
}

function strictBase64(value) {
  if (typeof value !== "string" || value.length === 0 || value.length % 4 !== 0 || !/^[A-Za-z0-9+/]+={0,2}$/.test(value)) return false;
  try {
    return Buffer.from(value, "base64").toString("base64") === value;
  } catch {
    return false;
  }
}

function publicKeyFingerprint(publicKey) {
  return sha256(publicKey.export({ type: "spki", format: "der" }));
}

function endorsementMaterial(endorsement) {
  return {
    protocol: MATERIAL_PROTOCOL,
    endorsement_protocol: SEMANTIC_RELEASE_ENDORSEMENT_PROTOCOL,
    endorsement_version: ENDORSEMENT_VERSION,
    algorithm: ALGORITHM,
    proof_sha256: endorsement.proof_sha256,
    release_id: endorsement.release_id,
    after_manifest_root_sha256: endorsement.after_manifest_root_sha256,
    lineage_head_sha256: endorsement.lineage_head_sha256,
    signer: endorsement.signer ?? null,
    endorsed_at: endorsement.endorsed_at,
    public_key_sha256: endorsement.public_key_sha256
  };
}

function normalizeTrustedKey(entry) {
  if (!entry || typeof entry !== "object" || Array.isArray(entry)) throw new TypeError("trusted_keys entries must be objects");
  if (!validHash(entry.public_key_sha256)) throw new TypeError("trusted key fingerprint must be lowercase SHA-256 hex");
  if (entry.signer !== undefined && entry.signer !== null && typeof entry.signer !== "string") throw new TypeError("trusted key signer must be string or null");
  return { public_key_sha256: entry.public_key_sha256, signer: entry.signer ?? null };
}

function compareTrustedKeys(a, b) {
  if (a.public_key_sha256 !== b.public_key_sha256) return a.public_key_sha256 < b.public_key_sha256 ? -1 : 1;
  const left = a.signer ?? "";
  const right = b.signer ?? "";
  return left < right ? -1 : left > right ? 1 : 0;
}

export function fingerprintSemanticReleaseQuorumPolicy(policy) {
  const validation = validateSemanticReleaseQuorumPolicy(policy);
  if (!validation.valid) throw new TypeError(`invalid quorum policy: ${validation.reason}`);
  return sha256(Buffer.from(canonicalJSONStringify({
    protocol: SEMANTIC_RELEASE_QUORUM_POLICY_PROTOCOL,
    policy_id: validation.policy_id,
    threshold: validation.threshold,
    trusted_keys: validation.trusted_keys.map(entry => ({ ...entry })).sort(compareTrustedKeys)
  }), "utf8"));
}

export function validateSemanticReleaseQuorumPolicy(policy) {
  try {
    if (!policy || policy.protocol !== SEMANTIC_RELEASE_QUORUM_POLICY_PROTOCOL) return { valid: false, reason: "invalid_policy_protocol" };
    if (!Array.isArray(policy.trusted_keys) || policy.trusted_keys.length === 0) return { valid: false, reason: "empty_trusted_keys" };
    if (!Number.isSafeInteger(policy.threshold) || policy.threshold < 1 || policy.threshold > policy.trusted_keys.length) return { valid: false, reason: "invalid_threshold" };
    if (policy.policy_id !== undefined && policy.policy_id !== null && typeof policy.policy_id !== "string") return { valid: false, reason: "invalid_policy_id" };
    const trustedKeys = policy.trusted_keys.map(normalizeTrustedKey);
    const fingerprints = trustedKeys.map(entry => entry.public_key_sha256);
    if (new Set(fingerprints).size !== fingerprints.length) return { valid: false, reason: "duplicate_trusted_key" };
    return { valid: true, reason: null, policy_id: policy.policy_id ?? null, threshold: policy.threshold, trusted_keys: trustedKeys };
  } catch {
    return { valid: false, reason: "invalid_policy_structure" };
  }
}

export function createSemanticReleaseEndorsement(proof, privateKeyPem, { signer = null, timestamp = new Date().toISOString() } = {}) {
  const proofVerification = verifySemanticReleaseProof(proof);
  if (!proofVerification.verified) throw new Error("Semantic Release Endorsement requires a fully verified Semantic Release Proof.");
  if (!validTimestamp(timestamp)) throw new TypeError("Semantic Release Endorsement requires a valid timestamp.");
  const privateKey = crypto.createPrivateKey(privateKeyPem);
  if (privateKey.asymmetricKeyType !== "ed25519") throw new TypeError("Semantic Release Endorsement requires an Ed25519 private key.");
  const publicKey = crypto.createPublicKey(privateKey);
  const endorsement = {
    protocol: SEMANTIC_RELEASE_ENDORSEMENT_PROTOCOL,
    version: ENDORSEMENT_VERSION,
    algorithm: ALGORITHM,
    material_protocol: MATERIAL_PROTOCOL,
    proof_sha256: proof.proof_sha256,
    release_id: proof.release_id ?? null,
    after_manifest_root_sha256: proof.after_manifest_root_sha256,
    lineage_head_sha256: proof.lineage_head_sha256,
    signer,
    endorsed_at: timestamp,
    public_key_sha256: publicKeyFingerprint(publicKey),
    public_key_pem: publicKey.export({ type: "spki", format: "pem" }).toString()
  };
  const material = Buffer.from(canonicalJSONStringify(endorsementMaterial(endorsement)), "utf8");
  endorsement.endorsement_sha256 = sha256(material);
  endorsement.signature_base64 = crypto.sign(null, material, privateKey).toString("base64");
  return endorsement;
}

export function verifySemanticReleaseEndorsement(endorsement, proof) {
  const base = { verified: false, proof_binding_valid: false, hash_valid: false, signature_valid: false, public_key_fingerprint_valid: false, signer: null, public_key_sha256: null, reason: null };
  try {
    const proofVerification = verifySemanticReleaseProof(proof);
    if (!proofVerification.verified) return { ...base, reason: "invalid_semantic_release_proof" };
    if (!endorsement || endorsement.protocol !== SEMANTIC_RELEASE_ENDORSEMENT_PROTOCOL || endorsement.version !== ENDORSEMENT_VERSION || endorsement.algorithm !== ALGORITHM || endorsement.material_protocol !== MATERIAL_PROTOCOL) return { ...base, reason: "invalid_endorsement_contract" };
    if (!validTimestamp(endorsement.endorsed_at) || !validHash(endorsement.public_key_sha256) || !validHash(endorsement.endorsement_sha256) || !strictBase64(endorsement.signature_base64)) return { ...base, reason: "invalid_endorsement_fields" };
    const proofBindingValid = endorsement.proof_sha256 === proof.proof_sha256 && endorsement.release_id === (proof.release_id ?? null) && endorsement.after_manifest_root_sha256 === proof.after_manifest_root_sha256 && endorsement.lineage_head_sha256 === proof.lineage_head_sha256;
    if (!proofBindingValid) return { ...base, reason: "proof_binding_mismatch" };
    const material = Buffer.from(canonicalJSONStringify(endorsementMaterial(endorsement)), "utf8");
    const hashValid = sha256(material) === endorsement.endorsement_sha256;
    const publicKey = crypto.createPublicKey(endorsement.public_key_pem);
    if (publicKey.asymmetricKeyType !== "ed25519") return { ...base, proof_binding_valid: true, hash_valid: hashValid, reason: "unsupported_public_key_type" };
    const fingerprintValid = publicKeyFingerprint(publicKey) === endorsement.public_key_sha256;
    const signatureValid = crypto.verify(null, material, publicKey, Buffer.from(endorsement.signature_base64, "base64"));
    const verified = hashValid && fingerprintValid && signatureValid;
    return { ...base, verified, proof_binding_valid: true, hash_valid: hashValid, signature_valid: signatureValid, public_key_fingerprint_valid: fingerprintValid, signer: verified ? (endorsement.signer ?? null) : null, public_key_sha256: endorsement.public_key_sha256, reason: verified ? null : !hashValid ? "endorsement_hash_mismatch" : !fingerprintValid ? "public_key_fingerprint_mismatch" : "signature_invalid" };
  } catch {
    return { ...base, reason: "endorsement_verification_error" };
  }
}

export function verifySemanticReleaseQuorum(proof, endorsements, policy, { expectedPolicySha256 = null } = {}) {
  const base = { verified: false, semantic_proof_valid: false, policy_valid: false, policy_sha256_valid: expectedPolicySha256 === null ? null : false, threshold: null, valid_trusted_endorsements: 0, unique_trusted_keys: [], rejected_endorsements: [], policy_id: null, policy_sha256: null, reason: null };
  const proofVerification = verifySemanticReleaseProof(proof);
  if (!proofVerification.verified) return { ...base, reason: "invalid_semantic_release_proof" };
  const policyValidation = validateSemanticReleaseQuorumPolicy(policy);
  if (!policyValidation.valid) return { ...base, semantic_proof_valid: true, reason: policyValidation.reason };
  const policySha256 = fingerprintSemanticReleaseQuorumPolicy(policy);
  if (expectedPolicySha256 !== null && expectedPolicySha256 !== policySha256) return { ...base, semantic_proof_valid: true, policy_valid: true, threshold: policyValidation.threshold, policy_id: policyValidation.policy_id, policy_sha256: policySha256, policy_sha256_valid: false, reason: "policy_fingerprint_mismatch" };
  if (!Array.isArray(endorsements)) return { ...base, semantic_proof_valid: true, policy_valid: true, threshold: policyValidation.threshold, policy_id: policyValidation.policy_id, policy_sha256: policySha256, policy_sha256_valid: expectedPolicySha256 === null ? null : true, reason: "invalid_endorsements" };

  const trusted = new Map(policyValidation.trusted_keys.map(entry => [entry.public_key_sha256, entry]));
  const accepted = new Map();
  const rejected = [];
  for (let index = 0; index < endorsements.length; index += 1) {
    const endorsement = endorsements[index];
    const verification = verifySemanticReleaseEndorsement(endorsement, proof);
    if (!verification.verified) { rejected.push({ index, reason: verification.reason }); continue; }
    const trust = trusted.get(verification.public_key_sha256);
    if (!trust) { rejected.push({ index, reason: "endorsement_key_not_trusted" }); continue; }
    if (trust.signer !== null && trust.signer !== verification.signer) { rejected.push({ index, reason: "endorsement_signer_constraint_mismatch" }); continue; }
    if (accepted.has(verification.public_key_sha256)) { rejected.push({ index, reason: "duplicate_endorsement_key" }); continue; }
    accepted.set(verification.public_key_sha256, { signer: verification.signer });
  }

  const verified = accepted.size >= policyValidation.threshold;
  return {
    ...base,
    verified,
    semantic_proof_valid: true,
    policy_valid: true,
    policy_sha256_valid: expectedPolicySha256 === null ? null : true,
    threshold: policyValidation.threshold,
    valid_trusted_endorsements: accepted.size,
    unique_trusted_keys: [...accepted.keys()].sort(),
    rejected_endorsements: rejected,
    policy_id: policyValidation.policy_id,
    policy_sha256: policySha256,
    reason: verified ? null : "quorum_not_met"
  };
}
