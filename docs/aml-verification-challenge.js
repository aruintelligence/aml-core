// ĀML verification challenge — SHIPPED reference prototype.
// A verifier-generated random challenge binds a later session attestation to a fresh request.
// This is replay resistance for the prototype flow, not identity or authorization.

function bytesToBase64Url(bytes) {
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

export function createVerificationChallenge({ ttl_ms = 120000 } = {}) {
  if (!globalThis.crypto?.getRandomValues) throw new Error('AML_CHALLENGE_CRYPTO_UNAVAILABLE');
  const nonce = new Uint8Array(32);
  crypto.getRandomValues(nonce);
  const issued = Date.now();
  return {
    schema: 'aml-verification-challenge/1',
    prototype: true,
    nonce: bytesToBase64Url(nonce),
    issued_at: new Date(issued).toISOString(),
    expires_at: new Date(issued + ttl_ms).toISOString()
  };
}

export function verifyVerificationChallenge(challenge, { now = Date.now() } = {}) {
  if (!challenge || challenge.schema !== 'aml-verification-challenge/1') {
    return { valid: false, reason: 'AML_CHALLENGE_INVALID' };
  }
  if (typeof challenge.nonce !== 'string' || challenge.nonce.length < 32) {
    return { valid: false, reason: 'AML_CHALLENGE_NONCE_INVALID' };
  }
  const issued = Date.parse(challenge.issued_at);
  const expires = Date.parse(challenge.expires_at);
  if (!Number.isFinite(issued) || !Number.isFinite(expires) || expires <= issued) {
    return { valid: false, reason: 'AML_CHALLENGE_TIME_INVALID' };
  }
  if (now > expires) return { valid: false, reason: 'AML_CHALLENGE_EXPIRED' };
  return { valid: true, reason: 'AML_CHALLENGE_VALID' };
}
