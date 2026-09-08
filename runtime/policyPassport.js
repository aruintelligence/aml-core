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

export function createPolicyPassport({ subject = null, profile, preferences = {}, issued_at = null, expires_at = null } = {}) {
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

export function verifyPolicyPassport(passport, { now = null } = {}) {
  if (!passport || passport.type !== "aml-policy-passport/1") return { valid: false, reason: "invalid_type" };
  const { passport_hash, ...body } = passport;
  if (digest(body) !== passport_hash) return { valid: false, reason: "hash_mismatch" };
  if (now && passport.expires_at && new Date(now) >= new Date(passport.expires_at)) return { valid: false, reason: "expired" };
  return { valid: true, reason: null, passport_hash };
}

export function passportContext(passport) {
  const verification = verifyPolicyPassport(passport);
  if (!verification.valid) return { policy_passport_valid: false };
  return {
    policy_passport_valid: true,
    policy_profile: passport.profile,
    policy_preferences: passport.preferences,
    policy_passport_hash: passport.passport_hash
  };
}
