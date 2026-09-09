import crypto from "node:crypto";
import { canonicalJSONStringify } from "../protocol/canonicalJson.js";
import { verifySemanticReleaseProof } from "../compiler/semanticReleaseProof.js";
import { verifyTrustedSemanticReleaseProof } from "./releaseKeyTrust.js";
import { verifySemanticReleaseQuorum } from "./semanticReleaseQuorum.js";
import {
  AML_SEMANTIC_RELEASE_PREDICATE_V1,
  createInTotoSemanticReleaseStatement
} from "../compiler/inTotoSemanticRelease.js";

function sameCanonical(a, b) {
  try {
    return canonicalJSONStringify(a) === canonicalJSONStringify(b);
  } catch {
    return false;
  }
}

function sha256(bytes) {
  return crypto.createHash("sha256").update(bytes).digest("hex");
}

function verifiedStatement(entry) {
  return entry?.verificationResult?.statement ?? null;
}

export function buildGitHubAttestationVerifyArgs({
  proofFile,
  repo,
  allowSelfHosted = false,
  signerWorkflow = null,
  bundle = null
} = {}) {
  if (typeof proofFile !== "string" || proofFile.length === 0) throw new TypeError("proofFile is required");
  if (typeof repo !== "string" || !/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(repo)) throw new TypeError("repo must be OWNER/REPOSITORY");
  const args = [
    "attestation", "verify", proofFile,
    "--repo", repo,
    "--predicate-type", AML_SEMANTIC_RELEASE_PREDICATE_V1,
    "--signer-repo", repo,
    "--format", "json"
  ];
  if (!allowSelfHosted) args.push("--deny-self-hosted-runners");
  if (signerWorkflow) args.push("--signer-workflow", signerWorkflow);
  if (bundle) args.push("--bundle", bundle);
  return args;
}

export function verifyGitHubSemanticAttestationEvidence({
  ghVerification,
  proof,
  proofBytes,
  trustPolicy = null,
  expectedTrustPolicySha256 = null,
  quorumEndorsements = null,
  quorumPolicy = null,
  expectedQuorumPolicySha256 = null
} = {}) {
  const quorumRequired = quorumPolicy !== null || quorumEndorsements !== null || expectedQuorumPolicySha256 !== null;
  const base = {
    verified: false,
    github_attestation_verified: false,
    proof_file_digest_valid: false,
    predicate_type_valid: false,
    predicate_binding_valid: false,
    release_proof_valid: false,
    release_key_trust_required: trustPolicy !== null,
    release_key_trusted: null,
    trust_policy_fingerprint_valid: expectedTrustPolicySha256 === null ? null : false,
    trust_policy_id: null,
    trust_policy_sha256: null,
    quorum_required: quorumRequired,
    quorum_verified: quorumRequired ? false : null,
    quorum_threshold: null,
    quorum_valid_trusted_endorsements: null,
    quorum_policy_id: null,
    quorum_policy_sha256: null,
    quorum_policy_fingerprint_valid: expectedQuorumPolicySha256 === null ? null : false,
    matched_attestations: 0,
    proof_file_sha256: null,
    signer: null,
    public_key_sha256: null,
    release_id: null,
    meaning_state_sha256: null,
    proof_sha256: null,
    reason: null
  };

  try {
    if (!Array.isArray(ghVerification) || ghVerification.length === 0) return { ...base, reason: "no_verified_attestations" };
    if (!Buffer.isBuffer(proofBytes) && !(proofBytes instanceof Uint8Array)) return { ...base, reason: "invalid_proof_bytes" };
    if (expectedTrustPolicySha256 !== null && trustPolicy === null) return { ...base, reason: "trust_policy_required_for_fingerprint" };
    if (quorumRequired && (quorumPolicy === null || quorumEndorsements === null)) return { ...base, reason: "quorum_policy_and_endorsements_required" };
    if (expectedQuorumPolicySha256 !== null && quorumPolicy === null) return { ...base, reason: "quorum_policy_required_for_fingerprint" };

    const proofVerification = verifySemanticReleaseProof(proof);
    if (!proofVerification.verified) return { ...base, reason: "invalid_semantic_release_proof" };

    let trustVerification = null;
    if (trustPolicy !== null) {
      trustVerification = verifyTrustedSemanticReleaseProof(proof, trustPolicy, { expected_policy_sha256: expectedTrustPolicySha256 });
      if (!trustVerification.verified) {
        return {
          ...base,
          release_proof_valid: true,
          release_key_trusted: trustVerification.release_key_trusted,
          trust_policy_fingerprint_valid: trustVerification.policy_fingerprint_valid,
          trust_policy_id: trustVerification.policy_id ?? null,
          trust_policy_sha256: trustVerification.policy_sha256 ?? null,
          public_key_sha256: proof.public_key_sha256 ?? null,
          release_id: proof.release_id ?? null,
          reason: trustVerification.reason || "release_key_not_trusted"
        };
      }
    }

    let quorumVerification = null;
    if (quorumRequired) {
      quorumVerification = verifySemanticReleaseQuorum(proof, quorumEndorsements, quorumPolicy, { expectedPolicySha256: expectedQuorumPolicySha256 });
      if (!quorumVerification.verified) {
        return {
          ...base,
          release_proof_valid: true,
          release_key_trusted: trustPolicy === null ? null : true,
          trust_policy_fingerprint_valid: trustVerification?.policy_fingerprint_valid ?? null,
          trust_policy_id: trustVerification?.policy_id ?? null,
          trust_policy_sha256: trustVerification?.policy_sha256 ?? null,
          quorum_verified: false,
          quorum_threshold: quorumVerification.threshold,
          quorum_valid_trusted_endorsements: quorumVerification.valid_trusted_endorsements,
          quorum_policy_id: quorumVerification.policy_id,
          quorum_policy_sha256: quorumVerification.policy_sha256,
          quorum_policy_fingerprint_valid: quorumVerification.policy_sha256_valid,
          public_key_sha256: proof.public_key_sha256 ?? null,
          release_id: proof.release_id ?? null,
          reason: quorumVerification.reason || "quorum_not_met"
        };
      }
    }

    const fileHash = sha256(proofBytes);
    const expectedPredicate = createInTotoSemanticReleaseStatement(proof).predicate;
    let matched = 0;
    let predicateTypeValid = false;
    let digestValid = false;
    let predicateValid = false;

    for (const entry of ghVerification) {
      const statement = verifiedStatement(entry);
      if (!statement || statement.predicateType !== AML_SEMANTIC_RELEASE_PREDICATE_V1) continue;
      predicateTypeValid = true;

      const subjects = Array.isArray(statement.subject) ? statement.subject : [];
      const thisDigestValid = subjects.some(subject => subject?.digest?.sha256 === fileHash);
      if (!thisDigestValid) continue;
      digestValid = true;

      if (!sameCanonical(statement.predicate, expectedPredicate)) continue;
      if (!sameCanonical(statement.predicate?.releaseProof, proof)) continue;
      predicateValid = true;
      matched += 1;
    }

    const verified = matched > 0;
    return {
      ...base,
      verified,
      github_attestation_verified: true,
      proof_file_digest_valid: digestValid,
      predicate_type_valid: predicateTypeValid,
      predicate_binding_valid: predicateValid,
      release_proof_valid: true,
      release_key_trusted: trustPolicy === null ? null : true,
      trust_policy_fingerprint_valid: trustVerification?.policy_fingerprint_valid ?? null,
      trust_policy_id: trustVerification?.policy_id ?? null,
      trust_policy_sha256: trustVerification?.policy_sha256 ?? null,
      quorum_verified: quorumRequired ? true : null,
      quorum_threshold: quorumVerification?.threshold ?? null,
      quorum_valid_trusted_endorsements: quorumVerification?.valid_trusted_endorsements ?? null,
      quorum_policy_id: quorumVerification?.policy_id ?? null,
      quorum_policy_sha256: quorumVerification?.policy_sha256 ?? null,
      quorum_policy_fingerprint_valid: quorumVerification?.policy_sha256_valid ?? null,
      matched_attestations: matched,
      proof_file_sha256: fileHash,
      signer: verified ? proofVerification.signer : null,
      public_key_sha256: proof.public_key_sha256 ?? null,
      release_id: proof.release_id ?? null,
      meaning_state_sha256: proof.after_manifest_root_sha256,
      proof_sha256: proof.proof_sha256,
      reason: verified ? null : !predicateTypeValid ? "predicate_type_mismatch" : !digestValid ? "proof_file_digest_mismatch" : "predicate_binding_mismatch"
    };
  } catch {
    return { ...base, reason: "github_semantic_attestation_verification_error" };
  }
}
