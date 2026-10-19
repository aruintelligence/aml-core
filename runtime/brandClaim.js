import crypto from "node:crypto";
import { canonicalJSONStringify } from "../protocol/canonicalJson.js";
import { verifyRevocationRegistry } from "./revocationRegistry.js";
import { verifyOfficialBrandAuthorization, verifyBrandTrustRegistry } from "./brandTrust.js";

const digestPattern = /^[a-f0-9]{64}$/;

function failure(reason) {
  return { valid: false, official: false, claim_verified: false, reason };
}

function sha256(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function snapshot(value) {
  const canonical = canonicalJSONStringify(value);
  return { canonical, value: JSON.parse(canonical) };
}

/**
 * Check one exact brand-use claim against snapshots pinned in a buyer-held policy.
 * The policy and its source snapshots must be obtained through a trusted channel;
 * this function cannot establish their origin or whether newer snapshots exist.
 */
export function verifyBrandClaim(credential, trustRegistry, revocationRegistry, policy) {
  let claim;
  try {
    claim = snapshot(policy).value;
  } catch {
    return failure("invalid_claim_policy");
  }
  if (!claim || claim.type !== "aml-brand-claim-policy/1" ||
      ![claim.grantee, claim.mark, claim.permitted_use].every((value) => typeof value === "string" && value.trim()) ||
      !digestPattern.test(claim.trust_registry_sha256) ||
      !Object.hasOwn(claim, "revocation_head") ||
      !(claim.revocation_head === null || digestPattern.test(claim.revocation_head))) {
    return failure("invalid_claim_policy");
  }

  let roots;
  try {
    roots = snapshot(trustRegistry);
  } catch {
    return failure("invalid_trust_registry");
  }
  if (!verifyBrandTrustRegistry(roots.value).valid) return failure("invalid_trust_registry");
  const trustDigest = sha256(roots.canonical);
  if (trustDigest !== claim.trust_registry_sha256) return failure("trust_registry_snapshot_mismatch");

  if (revocationRegistry == null) return failure("revocation_registry_required");
  let revocations;
  try {
    revocations = snapshot(revocationRegistry).value;
  } catch {
    return failure("invalid_revocation_registry");
  }
  const revocation = verifyRevocationRegistry(revocations);
  if (!revocation.valid) return failure("invalid_revocation_registry");
  if (revocation.head !== claim.revocation_head) return failure("revocation_snapshot_mismatch");

  let presentedCredential;
  try {
    presentedCredential = snapshot(credential).value;
  } catch {
    return failure("invalid_credential");
  }

  // No caller-supplied clock: this checks the credential and root at the local instant.
  const result = verifyOfficialBrandAuthorization(presentedCredential, roots.value, {
    revocation_registry: revocations
  });
  if (!result.valid || !result.official) return { ...result, claim_verified: false };

  if (result.grantee !== claim.grantee) return { ...result, claim_verified: false, reason: "grantee_mismatch" };
  if (!result.marks.includes(claim.mark)) return { ...result, claim_verified: false, reason: "mark_not_permitted" };
  if (!result.permitted_uses.includes(claim.permitted_use)) {
    return { ...result, claim_verified: false, reason: "use_not_permitted" };
  }

  return {
    ...result,
    claim_verified: true,
    claim_scope: { grantee: claim.grantee, mark: claim.mark, permitted_use: claim.permitted_use },
    trust_registry_sha256: trustDigest,
    revocation_head: revocation.head,
    evidence_scope: "buyer_pinned_snapshots"
  };
}
