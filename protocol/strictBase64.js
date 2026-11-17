// Strict, canonical base64 for signatures (shared by every JS verifier).
//
// Node's Buffer.from(value, "base64") is lenient: it skips whitespace and
// other non-alphabet characters, stops at stray padding, accepts missing
// padding and base64url characters, and ignores non-zero unused trailing
// bits. Many different strings therefore decode to the same signature bytes,
// and JS used to accept strings that the Python and Go verifiers refuse.
//
// The one rule, identical in JS, Python and Go: a signature string is valid
// only if it is non-empty, uses the standard alphabet with "=" padding, and
// equals the standard base64 encoding of the bytes it decodes to (so there is
// exactly one accepted spelling of every signature). Length is capped before
// decoding.
export const MAX_SIGNATURE_BYTES = 512;
const MAX_SIGNATURE_CHARS = 4 * Math.ceil(MAX_SIGNATURE_BYTES / 3);
const STANDARD_BASE64 = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;
// Canonical 64-byte Ed25519 signature: 85 free characters, then a final
// character whose 4 unused low bits are zero, then "==".
export const ED25519_SIGNATURE_BASE64 = /^[A-Za-z0-9+/]{85}[AQgw]==$/;

// Returns the decoded bytes, or null when the value is not canonical base64.
export function decodeCanonicalBase64(value, { maxBytes = MAX_SIGNATURE_BYTES } = {}) {
  if (typeof value !== "string" || value.length === 0 || value.length > 4 * Math.ceil(maxBytes / 3)
    || !STANDARD_BASE64.test(value)) return null;
  const bytes = Buffer.from(value, "base64");
  if (bytes.length === 0 || bytes.length > maxBytes || bytes.toString("base64") !== value) return null;
  return bytes;
}

// Signature bytes for crypto.verify, or null (callers treat null as an
// invalid signature; never fall back to lenient decoding).
export function decodeSignatureBase64(value) {
  if (typeof value !== "string" || value.length > MAX_SIGNATURE_CHARS) return null;
  return decodeCanonicalBase64(value);
}

// Throwing form for verifiers that report failures through exceptions.
export function requireSignatureBase64(value) {
  const bytes = decodeSignatureBase64(value);
  if (bytes === null) throw new Error("signature_base64 is not canonical base64");
  return bytes;
}
