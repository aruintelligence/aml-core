import crypto from "node:crypto";
import { canonicalJSONStringify } from "../protocol/canonicalJson.js";

function fingerprint(publicKey) {
  return crypto.createHash("sha256").update(publicKey.export({ type: "spki", format: "der" })).digest("hex");
}

function validTimestamp(value) {
  return typeof value === "string" && Number.isFinite(Date.parse(value));
}

function validateTimes({ issued_at = null, expires_at = null } = {}) {
  if (issued_at !== null && !validTimestamp(issued_at)) return "invalid_issued_at";
  if (expires_at !== null && !validTimestamp(expires_at)) return "invalid_expires_at";
  if (issued_at !== null && expires_at !== null && Date.parse(expires_at) <= Date.parse(issued_at)) {
    return "invalid_time_window";
  }
  return null;
}

export function signCapabilityToken({ issuer, subject = null, audience = null, capabilities = [], issued_at = null, expires_at = null, nonce = null } = {}, privateKeyPem) {
  if (!issuer) throw new Error("issuer is required");
  if (!privateKeyPem) throw new Error("private key is required");
  const timeError = validateTimes({ issued_at, expires_at });
  if (timeError) throw new Error(timeError);

  const body = {
    type: "aml-capability-token/1",
    issuer,
    subject,
    audience,
    capabilities: [...new Set(capabilities)].sort(),
    issued_at,
    expires_at,
    nonce
  };

  const privateKey = crypto.createPrivateKey(privateKeyPem);
  const publicKey = crypto.createPublicKey(privateKey);
  const message = Buffer.from(canonicalJSONStringify(body));

  return {
    ...body,
    public_key_pem: publicKey.export({ type: "spki", format: "pem" }).toString(),
    public_key_fingerprint: fingerprint(publicKey),
    signature_base64: crypto.sign(null, message, privateKey).toString("base64")
  };
}

export function verifyCapabilityToken(token, { now = null, audience = null, requiredCapability = null } = {}) {
  if (!token || token.type !== "aml-capability-token/1") return { valid: false, reason: "invalid_type" };
  const { public_key_pem, public_key_fingerprint, signature_base64, ...body } = token;

  try {
    const publicKey = crypto.createPublicKey(public_key_pem);
    if (fingerprint(publicKey) !== public_key_fingerprint) return { valid: false, reason: "fingerprint_mismatch" };
    const signatureValid = crypto.verify(null, Buffer.from(canonicalJSONStringify(body)), publicKey, Buffer.from(signature_base64, "base64"));
    if (!signatureValid) return { valid: false, reason: "signature_invalid" };
  } catch {
    return { valid: false, reason: "signature_invalid" };
  }

  const timeError = validateTimes(token);
  if (timeError) return { valid: false, reason: timeError };
  if (now !== null && !validTimestamp(now)) return { valid: false, reason: "invalid_now" };
  if (now && token.expires_at && Date.parse(now) >= Date.parse(token.expires_at)) return { valid: false, reason: "expired" };
  if (audience && token.audience !== audience) return { valid: false, reason: "audience_mismatch" };
  if (requiredCapability && !token.capabilities.includes(requiredCapability)) return { valid: false, reason: "capability_missing" };

  return { valid: true, reason: null, issuer: token.issuer, subject: token.subject, capabilities: token.capabilities };
}
