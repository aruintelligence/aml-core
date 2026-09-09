import crypto from "node:crypto";

function stable(value) {
  if (Array.isArray(value)) return value.map(stable);
  if (value && typeof value === "object") {
    return Object.fromEntries(Object.keys(value).sort().map((key) => [key, stable(value[key])]));
  }
  return value;
}

function digest(value) {
  return crypto.createHash("sha256").update(JSON.stringify(stable(value))).digest("hex");
}

function parseTimestamp(value) {
  if (typeof value !== "string" || value.trim() === "") return null;
  const timestamp = Date.parse(value);
  return Number.isFinite(timestamp) ? timestamp : null;
}

function requireTimestamp(value, field) {
  if (value !== null && value !== undefined && parseTimestamp(value) === null) {
    throw new Error(`${field} must be a valid timestamp`);
  }
}

function requireValidWindow(issuedAt, expiresAt) {
  const issued = issuedAt === null || issuedAt === undefined ? null : parseTimestamp(issuedAt);
  const expires = expiresAt === null || expiresAt === undefined ? null : parseTimestamp(expiresAt);
  if (issued !== null && expires !== null && expires <= issued) {
    throw new Error("expires_at must be after issued_at");
  }
}

export function createPolicyPassport({ subject = null, profile, preferences = {}, issued_at = null, expires_at = null } = {}) {
  requireTimestamp(issued_at, "issued_at");
  requireTimestamp(expires_at, "expires_at");
  requireValidWindow(issued_at, expires_at);

  const body = {
    type: "aml-policy-passport/1",
    subject,
    profile,
    preferences: stable(preferences),
    issued_at,
    expires_at
  };
  return { ...body, passport_hash: digest(body) };
}

export function verifyPolicyPassport(passport, { now = new Date().toISOString() } = {}) {
  try {
    if (!passport || typeof passport !== "object" || Array.isArray(passport) || passport.type !== "aml-policy-passport/1") {
      return { valid: false, reason: "invalid_type" };
    }
    const { passport_hash, ...body } = passport;
    if (typeof passport_hash !== "string" || digest(body) !== passport_hash) {
      return { valid: false, reason: "hash_mismatch" };
    }

    const issuedAt = passport.issued_at === null || passport.issued_at === undefined
      ? null
      : parseTimestamp(passport.issued_at);
    if (passport.issued_at !== null && passport.issued_at !== undefined && issuedAt === null) {
      return { valid: false, reason: "invalid_issued_at" };
    }

    const expiresAt = passport.expires_at === null || passport.expires_at === undefined
      ? null
      : parseTimestamp(passport.expires_at);
    if (passport.expires_at !== null && passport.expires_at !== undefined && expiresAt === null) {
      return { valid: false, reason: "invalid_expires_at" };
    }
    if (issuedAt !== null && expiresAt !== null && expiresAt <= issuedAt) {
      return { valid: false, reason: "invalid_time_window" };
    }

    if (now === null) {
      return { valid: true, reason: null, passport_hash, temporal_validation: "skipped_explicitly" };
    }
    const nowTimestamp = parseTimestamp(now);
    if (nowTimestamp === null) return { valid: false, reason: "invalid_now" };
    if (issuedAt !== null && nowTimestamp < issuedAt) return { valid: false, reason: "not_yet_valid" };
    if (expiresAt !== null && nowTimestamp >= expiresAt) return { valid: false, reason: "expired" };

    return { valid: true, reason: null, passport_hash, temporal_validation: "enforced" };
  } catch {
    return { valid: false, reason: "verification_error" };
  }
}

export function passportContext(passport, options = {}) {
  const verification = verifyPolicyPassport(passport, options);
  if (!verification.valid) return { policy_passport_valid: false };
  return {
    policy_passport_valid: true,
    policy_profile: passport.profile,
    policy_preferences: passport.preferences,
    policy_passport_hash: passport.passport_hash
  };
}
