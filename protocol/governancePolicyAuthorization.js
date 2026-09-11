import crypto from "node:crypto";
import { canonicalJSONStringify } from "./canonicalJson.js";
import { verifyDelegationChain } from "../runtime/trustDelegation.js";

export const AML_GOVERNANCE_POLICY_TRANSITION = "aml-governance-policy-transition/1";
export const AML_GOVERNANCE_POLICY_TRANSITION_AUTHORIZATION = "aml-governance-policy-transition-authorization/1";
export const AML_GOVERNANCE_POLICY_TRANSITION_AUTHORIZATION_VERIFICATION = "aml-governance-policy-transition-authorization-verification/1";

function fingerprint(publicKeyPem) {
  const key = crypto.createPublicKey(publicKeyPem);
  const der = key.export({ type: "spki", format: "der" });
  return crypto.createHash("sha256").update(der).digest("hex");
}

function material(transition) {
  return Buffer.from(canonicalJSONStringify(transition), "utf8");
}

function normalizeUpdate(update = {}) {
  const normalized = {};
  for (const key of ["profile", "mode", "failure_mode", "context", "context_mode"]) {
    if (update[key] !== undefined) normalized[key] = structuredClone(update[key]);
  }
  return normalized;
}

function verifyDelegatedAuthority(signature, { trusted, revoked, requiredScope, now, allowDelegatedAuthority }) {
  if (!allowDelegatedAuthority || !Array.isArray(signature.delegation_chain) || signature.delegation_chain.length === 0) {
    return { valid: false, root_fingerprint_sha256: null, reason: "delegated authority unavailable" };
  }

  const chain = signature.delegation_chain;
  const rootFingerprint = chain[0]?.issuer_key_fingerprint || null;
  if (!rootFingerprint || !trusted.has(rootFingerprint)) {
    return { valid: false, root_fingerprint_sha256: rootFingerprint, reason: "delegation root not trusted" };
  }

  for (const delegation of chain) {
    for (const keyFp of [delegation?.issuer_key_fingerprint, delegation?.delegate_key_fingerprint]) {
      if (keyFp && revoked.has(keyFp)) {
        return { valid: false, root_fingerprint_sha256: rootFingerprint, reason: "delegation chain contains revoked key" };
      }
    }
  }

  const verified = verifyDelegationChain(chain, {
    rootKeyFingerprint: rootFingerprint,
    now: now || null,
    requiredCapability: requiredScope
  });
  if (!verified.valid) {
    return { valid: false, root_fingerprint_sha256: rootFingerprint, reason: `delegation chain invalid: ${verified.reason}` };
  }
  if (verified.leaf_key_fingerprint !== signature.public_key_fingerprint_sha256) {
    return { valid: false, root_fingerprint_sha256: rootFingerprint, reason: "delegation leaf does not match signing key" };
  }

  return {
    valid: true,
    root_fingerprint_sha256: rootFingerprint,
    leaf_fingerprint_sha256: verified.leaf_key_fingerprint,
    reason: null
  };
}

export function createGovernancePolicyTransition({ transmission, expected_policy_epoch, previous_policy_sha256, update }) {
  if (typeof transmission !== "string" || transmission.length === 0) throw new Error("transmission is required");
  if (!Number.isInteger(expected_policy_epoch) || expected_policy_epoch < 0) throw new Error("expected_policy_epoch must be a non-negative integer");
  if (typeof previous_policy_sha256 !== "string" || !/^[a-f0-9]{64}$/.test(previous_policy_sha256)) throw new Error("previous_policy_sha256 must be SHA-256 hex");
  const normalizedUpdate = normalizeUpdate(update);
  if (Object.keys(normalizedUpdate).length === 0) throw new Error("policy transition update cannot be empty");
  return {
    protocol: AML_GOVERNANCE_POLICY_TRANSITION,
    transmission,
    expected_policy_epoch,
    previous_policy_sha256,
    update: normalizedUpdate
  };
}

export function signGovernancePolicyTransition(transition, privateKeyPem, options = {}) {
  if (!transition || transition.protocol !== AML_GOVERNANCE_POLICY_TRANSITION) throw new Error("valid governance policy transition is required");
  const privateKey = crypto.createPrivateKey(privateKeyPem);
  if (privateKey.asymmetricKeyType !== "ed25519") throw new Error("policy transition signing requires an Ed25519 private key");
  const publicKey = crypto.createPublicKey(privateKey);
  const publicKeyPem = publicKey.export({ type: "spki", format: "pem" }).toString();
  const fp = fingerprint(publicKeyPem);
  return {
    algorithm: "Ed25519",
    key_id: options.key_id || `sha256:${fp}`,
    public_key_fingerprint_sha256: fp,
    public_key_pem: publicKeyPem,
    signature_base64: crypto.sign(null, material(transition), privateKey).toString("base64"),
    signer: options.signer || null,
    scope: options.scope || "governance-policy-transition",
    signed_at: options.signed_at || null,
    ...(Array.isArray(options.delegation_chain) && options.delegation_chain.length > 0
      ? { delegation_chain: structuredClone(options.delegation_chain) }
      : {})
  };
}

export function createGovernancePolicyTransitionAuthorization(transition, signatures = []) {
  if (!transition || transition.protocol !== AML_GOVERNANCE_POLICY_TRANSITION) throw new Error("valid governance policy transition is required");
  if (!Array.isArray(signatures) || signatures.length === 0) throw new Error("at least one signature is required");
  return {
    protocol: AML_GOVERNANCE_POLICY_TRANSITION_AUTHORIZATION,
    transition: structuredClone(transition),
    signatures: structuredClone(signatures)
  };
}

export function verifyGovernancePolicyTransitionAuthorization(authorization, policy = {}) {
  const errors = [];
  if (!authorization || authorization.protocol !== AML_GOVERNANCE_POLICY_TRANSITION_AUTHORIZATION) {
    return { protocol: AML_GOVERNANCE_POLICY_TRANSITION_AUTHORIZATION_VERIFICATION, valid: false, authorized: false, errors: ["unsupported policy-transition authorization protocol"] };
  }
  const transition = authorization.transition;
  if (!transition || transition.protocol !== AML_GOVERNANCE_POLICY_TRANSITION) errors.push("invalid transition protocol");

  const threshold = Number.isInteger(policy.threshold) && policy.threshold > 0 ? policy.threshold : 1;
  const trusted = new Set(policy.trusted_fingerprints || []);
  const revoked = new Set(policy.revoked_fingerprints || []);
  const requiredScope = policy.required_scope || "governance-policy-transition";
  const requireTrusted = policy.require_trusted_keys !== false;
  const allowDelegatedAuthority = policy.allow_delegated_authority === true;
  const seen = new Set();
  const eligible = [];
  const signature_results = [];

  for (const signature of authorization.signatures || []) {
    const resultErrors = [];
    let fp = null;
    let signatureValid = false;
    try {
      if (signature.algorithm !== "Ed25519") throw new Error("signature algorithm must be Ed25519");
      fp = fingerprint(signature.public_key_pem);
      if (fp !== signature.public_key_fingerprint_sha256) throw new Error("public key fingerprint mismatch");
      signatureValid = crypto.verify(null, material(transition), crypto.createPublicKey(signature.public_key_pem), Buffer.from(signature.signature_base64, "base64"));
      if (!signatureValid) resultErrors.push("signature verification failed");
    } catch (error) {
      resultErrors.push(error.message || String(error));
    }

    if (signature.scope !== requiredScope) resultErrors.push("signature scope mismatch");
    if (fp && revoked.has(fp)) resultErrors.push("signing key revoked");

    const directlyTrusted = fp != null && trusted.has(fp) && !revoked.has(fp);
    const delegated = fp
      ? verifyDelegatedAuthority(signature, { trusted, revoked, requiredScope, now: policy.now, allowDelegatedAuthority })
      : { valid: false, root_fingerprint_sha256: null, reason: "signing key unavailable" };
    const isTrusted = directlyTrusted || delegated.valid;

    if (requireTrusted && !isTrusted) {
      if (allowDelegatedAuthority && Array.isArray(signature.delegation_chain) && signature.delegation_chain.length > 0 && delegated.reason) {
        resultErrors.push(delegated.reason);
      } else {
        resultErrors.push("signing key not trusted by supplied policy");
      }
    }
    if (fp && seen.has(fp)) resultErrors.push("duplicate signing key");
    if (fp) seen.add(fp);

    const isEligible = signatureValid && signature.scope === requiredScope && !revoked.has(fp) && (!requireTrusted || isTrusted) && !resultErrors.includes("duplicate signing key");
    if (isEligible) eligible.push(fp);
    signature_results.push({
      fingerprint_sha256: fp,
      signature_valid: signatureValid,
      trusted_key: isTrusted,
      authority_source: directlyTrusted ? "direct" : delegated.valid ? "delegated" : null,
      delegation_root_fingerprint_sha256: delegated.valid ? delegated.root_fingerprint_sha256 : null,
      eligible: isEligible,
      errors: resultErrors
    });
  }

  const authorized = errors.length === 0 && eligible.length >= threshold;
  if (!authorized) errors.push(`eligible signature threshold not met: ${eligible.length}/${threshold}`);
  return {
    protocol: AML_GOVERNANCE_POLICY_TRANSITION_AUTHORIZATION_VERIFICATION,
    valid: authorized && errors.length === 0,
    authorized,
    threshold,
    eligible_signatures: eligible.length,
    distinct_eligible_fingerprints: eligible,
    transition,
    signature_results,
    errors
  };
}

export function transitionMatchesUpdate(transition, { transmission, policy_epoch, previous_policy_sha256, update }) {
  if (!transition || transition.protocol !== AML_GOVERNANCE_POLICY_TRANSITION) return false;
  return transition.transmission === transmission &&
    transition.expected_policy_epoch === policy_epoch &&
    transition.previous_policy_sha256 === previous_policy_sha256 &&
    canonicalJSONStringify(transition.update) === canonicalJSONStringify(normalizeUpdate(update));
}
