// ĀML verification challenge — SHIPPED reference prototype.
// A verifier-generated random challenge binds a later session attestation to a fresh request.
// This is replay resistance for the prototype flow, not identity or authorization.

import { assertBrowserJSON } from './aml-browser-integrity.js';

function bytesToBase64Url(bytes) {
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

// The challenge producer emits exact UTC milliseconds. Requiring that form
// prevents Date.parse calendar rollover and submillisecond truncation from
// giving another verifier a different freshness decision.
function canonicalChallengeTime(value) {
  if (typeof value !== 'string' ||
      !/^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z$/.test(value)) return NaN;
  const time = Date.parse(value);
  return Number.isFinite(time) && new Date(time).toISOString() === value &&
    !value.startsWith('0000-') ? time : NaN;
}

export function createVerificationChallenge({ ttl_ms = 120000 } = {}) {
  if (!Number.isSafeInteger(ttl_ms) || ttl_ms <= 0) {
    throw new Error('AML_CHALLENGE_TTL_INVALID');
  }
  if (!globalThis.crypto?.getRandomValues) throw new Error('AML_CHALLENGE_CRYPTO_UNAVAILABLE');
  const nonce = new Uint8Array(32);
  crypto.getRandomValues(nonce);
  const issued = Date.now();
  const expires = issued + ttl_ms;
  if (!Number.isFinite(expires) || Math.abs(expires) > 8.64e15) {
    throw new Error('AML_CHALLENGE_TTL_INVALID');
  }
  return {
    schema: 'aml-verification-challenge/1',
    prototype: true,
    nonce: bytesToBase64Url(nonce),
    issued_at: new Date(issued).toISOString(),
    expires_at: new Date(expires).toISOString()
  };
}

export function verifyVerificationChallenge(challenge, { now = Date.now() } = {}) {
  try {
    assertBrowserJSON(challenge);
    if (!challenge || challenge.schema !== 'aml-verification-challenge/1') {
      return { valid: false, reason: 'AML_CHALLENGE_INVALID' };
    }
    if (typeof challenge.nonce !== 'string' || challenge.nonce.length < 32) {
      return { valid: false, reason: 'AML_CHALLENGE_NONCE_INVALID' };
    }
    const issued = canonicalChallengeTime(challenge.issued_at);
    const expires = canonicalChallengeTime(challenge.expires_at);
    if (typeof now !== 'number' || !Number.isFinite(now) ||
        !Number.isFinite(issued) || !Number.isFinite(expires) || expires <= issued) {
      return { valid: false, reason: 'AML_CHALLENGE_TIME_INVALID' };
    }
    if (now < issued) return { valid: false, reason: 'AML_CHALLENGE_NOT_YET_VALID' };
    if (now > expires) return { valid: false, reason: 'AML_CHALLENGE_EXPIRED' };
    return { valid: true, reason: 'AML_CHALLENGE_VALID' };
  } catch (error) {
    return { valid: false, reason: error?.message || 'AML_CHALLENGE_INVALID' };
  }
}
