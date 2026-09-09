import crypto from "node:crypto";
import { canonicalJSONStringify } from "../protocol/canonicalJson.js";
import { AML_SEMANTIC_RELEASE_PREDICATE_V1 } from "../compiler/inTotoSemanticRelease.js";

export const RELEASE_AUTHORIZATION_PROFILE_PROTOCOL = "aml-release-authorization-profile/1";
export const RELEASE_AUTHORIZATION_PROFILE_MATERIAL_PROTOCOL = "aml-release-authorization-profile-material/1";

function sha256(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function validHash(value) {
  return typeof value === "string" && /^[a-f0-9]{64}$/.test(value);
}

function validRepo(value) {
  return typeof value === "string" && /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(value);
}

function normalize(profile) {
  return {
    protocol: RELEASE_AUTHORIZATION_PROFILE_PROTOCOL,
    profile_id: profile.profile_id ?? null,
    repository: profile.repository,
    signer_workflow: profile.signer_workflow ?? null,
    allow_self_hosted: profile.allow_self_hosted,
    predicate_type: profile.predicate_type,
    required_layers: {
      github_attestation: profile.required_layers.github_attestation,
      semantic_release_proof: profile.required_layers.semantic_release_proof,
      release_key_trust: profile.required_layers.release_key_trust,
      semantic_release_quorum: profile.required_layers.semantic_release_quorum
    },
    release_key_policy_sha256: profile.release_key_policy_sha256 ?? null,
    quorum_policy_sha256: profile.quorum_policy_sha256 ?? null
  };
}

export function validateReleaseAuthorizationProfile(profile) {
  try {
    if (!profile || profile.protocol !== RELEASE_AUTHORIZATION_PROFILE_PROTOCOL) return { valid: false, reason: "invalid_profile_protocol" };
    if (!validRepo(profile.repository)) return { valid: false, reason: "invalid_repository" };
    if (profile.profile_id !== undefined && profile.profile_id !== null && typeof profile.profile_id !== "string") return { valid: false, reason: "invalid_profile_id" };
    if (profile.signer_workflow !== undefined && profile.signer_workflow !== null && (typeof profile.signer_workflow !== "string" || profile.signer_workflow.length === 0)) return { valid: false, reason: "invalid_signer_workflow" };
    if (typeof profile.allow_self_hosted !== "boolean") return { valid: false, reason: "invalid_self_hosted_policy" };
    if (profile.predicate_type !== AML_SEMANTIC_RELEASE_PREDICATE_V1) return { valid: false, reason: "invalid_predicate_type" };
    if (!profile.required_layers || typeof profile.required_layers !== "object" || Array.isArray(profile.required_layers)) return { valid: false, reason: "invalid_required_layers" };
    const layerNames = ["github_attestation", "semantic_release_proof", "release_key_trust", "semantic_release_quorum"];
    for (const name of layerNames) if (typeof profile.required_layers[name] !== "boolean") return { valid: false, reason: "invalid_required_layers" };
    if (profile.required_layers.github_attestation !== true || profile.required_layers.semantic_release_proof !== true) return { valid: false, reason: "mandatory_layers_disabled" };

    if (profile.required_layers.release_key_trust) {
      if (!validHash(profile.release_key_policy_sha256)) return { valid: false, reason: "release_key_policy_hash_required" };
    } else if (profile.release_key_policy_sha256 !== undefined && profile.release_key_policy_sha256 !== null) {
      return { valid: false, reason: "unexpected_release_key_policy_hash" };
    }

    if (profile.required_layers.semantic_release_quorum) {
      if (!validHash(profile.quorum_policy_sha256)) return { valid: false, reason: "quorum_policy_hash_required" };
    } else if (profile.quorum_policy_sha256 !== undefined && profile.quorum_policy_sha256 !== null) {
      return { valid: false, reason: "unexpected_quorum_policy_hash" };
    }

    const normalized = normalize(profile);
    return { valid: true, reason: null, profile: normalized };
  } catch {
    return { valid: false, reason: "invalid_profile_structure" };
  }
}

export function releaseAuthorizationProfileFingerprint(profile) {
  const validation = validateReleaseAuthorizationProfile(profile);
  if (!validation.valid) throw new TypeError(`invalid release authorization profile: ${validation.reason}`);
  const material = {
    protocol: RELEASE_AUTHORIZATION_PROFILE_MATERIAL_PROTOCOL,
    profile: validation.profile
  };
  return sha256(Buffer.from(canonicalJSONStringify(material), "utf8"));
}

export function resolveReleaseAuthorizationProfile(profile, { expectedProfileSha256 = null } = {}) {
  const validation = validateReleaseAuthorizationProfile(profile);
  if (!validation.valid) return { valid: false, reason: validation.reason, profile_sha256: null, profile: null };
  const profileSha256 = releaseAuthorizationProfileFingerprint(validation.profile);
  if (expectedProfileSha256 !== null) {
    if (!validHash(expectedProfileSha256)) return { valid: false, reason: "invalid_expected_profile_sha256", profile_sha256: profileSha256, profile: validation.profile };
    if (expectedProfileSha256 !== profileSha256) return { valid: false, reason: "authorization_profile_fingerprint_mismatch", profile_sha256: profileSha256, profile: validation.profile };
  }
  return { valid: true, reason: null, profile_sha256: profileSha256, profile: validation.profile };
}
