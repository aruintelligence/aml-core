import { verifyBrandAuthorization } from "./brandAuthorization.js";

function validWindow(start, end) {
  return (start == null || (typeof start === "string" && Number.isFinite(Date.parse(start)))) &&
    (end == null || (typeof end === "string" && Number.isFinite(Date.parse(end)))) &&
    (start == null || end == null || Date.parse(start) < Date.parse(end));
}

export function verifyBrandTrustRegistry(registry) {
  if (!registry || registry.type !== "aml-brand-trust-roots/1") {
    return { valid: false, reason: "invalid_type" };
  }
  if (typeof registry.owner !== "string" || !registry.owner.trim()) {
    return { valid: false, reason: "invalid_owner" };
  }
  if (!["unprovisioned", "active", "rotating", "suspended"].includes(registry.status)) {
    return { valid: false, reason: "invalid_status" };
  }
  if (!Array.isArray(registry.active_keys) || !Array.isArray(registry.revoked_keys)) {
    return { valid: false, reason: "invalid_key_lists" };
  }
  const active = new Set();
  for (const entry of registry.active_keys) {
    if (!entry?.public_key_sha256 || typeof entry.public_key_sha256 !== "string") {
      return { valid: false, reason: "invalid_active_key" };
    }
    if (active.has(entry.public_key_sha256)) return { valid: false, reason: "duplicate_active_key" };
    if (!validWindow(entry.not_before, entry.not_after)) {
      return { valid: false, reason: "invalid_active_key_window" };
    }
    active.add(entry.public_key_sha256);
  }
  const revoked = new Set();
  for (const entry of registry.revoked_keys) {
    if (!entry?.public_key_sha256 || typeof entry.public_key_sha256 !== "string") {
      return { valid: false, reason: "invalid_revoked_key" };
    }
    revoked.add(entry.public_key_sha256);
  }
  for (const fingerprint of active) {
    if (revoked.has(fingerprint)) return { valid: false, reason: "key_active_and_revoked" };
  }
  return {
    valid: true,
    reason: null,
    owner: registry.owner ?? null,
    active_key_count: active.size,
    revoked_key_count: revoked.size
  };
}

export function verifyOfficialBrandAuthorization(credential, trustRegistry, options = {}) {
  const now = options.now == null ? new Date().toISOString() : options.now;
  const clockSource = options.now == null ? "local_system" : "caller_supplied";
  const registryVerification = verifyBrandTrustRegistry(trustRegistry);
  if (!registryVerification.valid) {
    return { valid: false, official: false, reason: "invalid_trust_registry", registry_reason: registryVerification.reason };
  }
  if (trustRegistry.status !== "active" && trustRegistry.status !== "rotating") {
    return { valid: false, official: false, reason: "trust_registry_inactive" };
  }

  const credentialVerification = verifyBrandAuthorization(credential, {
    ...options,
    now,
    expected_issuer: trustRegistry.owner
  });

  if (!credentialVerification.valid) {
    return { ...credentialVerification, official: false };
  }

  const revoked = trustRegistry.revoked_keys.some((entry) => entry.public_key_sha256 === credential.public_key_sha256);
  if (revoked) return { valid: false, official: false, reason: "signing_key_revoked" };

  const trusted = trustRegistry.active_keys.find((entry) => entry.public_key_sha256 === credential.public_key_sha256) ?? null;
  if (!trusted) return { valid: false, official: false, reason: "untrusted_signing_key" };

  if (trusted.not_before && Date.parse(now) < Date.parse(trusted.not_before)) {
    return { valid: false, official: false, reason: "signing_key_not_yet_valid" };
  }
  if (trusted.not_after && Date.parse(now) >= Date.parse(trusted.not_after)) {
    return { valid: false, official: false, reason: "signing_key_expired" };
  }

  return {
    ...credentialVerification,
    official: true,
    clock_source: clockSource,
    trust_root: {
      key_id: trusted.key_id ?? null,
      public_key_sha256: trusted.public_key_sha256,
      purpose: trusted.purpose ?? null
    }
  };
}
