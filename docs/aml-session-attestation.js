// ĀML session attestation — SHIPPED reference prototype.
// Binds one sealed browser evidence hash to one verifier challenge using an ephemeral P-256 key.
// This proves possession of the ephemeral session key and exact payload binding.
// It does NOT prove human identity, organization identity, authorization, intent truth, safety, or policy quality.

import { assertBrowserJSON, canonicalJSONStringifyBrowser, sha256Browser } from './aml-browser-integrity.js';
import { verifyBrowserEvidence } from './aml-browser-evidence.js';
import { verifyVerificationChallenge } from './aml-verification-challenge.js';

let sessionKeyPair = null;
let sessionPublicJwk = null;
let sessionKeyFingerprint = null;

function bytesToBase64Url(bytes) {
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

function base64UrlToBytes(value) {
  const normalized = value.replace(/-/g, '+').replace(/_/g, '/');
  const padded = normalized + '='.repeat((4 - normalized.length % 4) % 4);
  const binary = atob(padded);
  return Uint8Array.from(binary, (char) => char.charCodeAt(0));
}

// Web Crypto verifies decoded bytes. Require their unique unpadded base64url
// spelling so another runtime cannot reject the same purported witness.
function canonicalBytes(value, length, encodedLength, reason) {
  if (typeof value !== 'string' || value.length !== encodedLength ||
      !/^[A-Za-z0-9_-]+$/.test(value)) throw new Error(reason);
  const bytes = base64UrlToBytes(value);
  if (bytes.length !== length || bytesToBase64Url(bytes) !== value) throw new Error(reason);
  return bytes;
}

async function ensureSessionKey() {
  if (sessionKeyPair) return;
  if (!globalThis.crypto?.subtle) throw new Error('AML_SESSION_CRYPTO_UNAVAILABLE');
  sessionKeyPair = await crypto.subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-256' },
    true,
    ['sign', 'verify']
  );
  sessionPublicJwk = await crypto.subtle.exportKey('jwk', sessionKeyPair.publicKey);
  sessionKeyFingerprint = await sha256Browser(sessionPublicJwk);
}

export function sessionAttestationPayload(attestation) {
  assertBrowserJSON(attestation);
  if (!attestation || attestation.schema !== 'aml-session-attestation/1') {
    throw new Error('AML_SESSION_ATTESTATION_INVALID');
  }
  const { signature, ...payload } = attestation;
  return payload;
}

export async function createSessionAttestation({
  evidence = globalThis.__AML_EVIDENCE__,
  challenge
} = {}) {
  const evidenceCheck = await verifyBrowserEvidence(evidence);
  if (!evidenceCheck.valid) throw new Error('AML_SESSION_EVIDENCE_INVALID');
  const challengeCheck = verifyVerificationChallenge(challenge);
  if (!challengeCheck.valid) throw new Error(challengeCheck.reason);

  await ensureSessionKey();
  const issuedAt = new Date().toISOString();
  const attestation = {
    schema: 'aml-session-attestation/1',
    prototype: true,
    algorithm: 'ECDSA-P256-SHA256',
    evidence_hash: evidence.integrity.value,
    challenge_nonce: challenge.nonce,
    challenge_expires_at: challenge.expires_at,
    issued_at: issuedAt,
    session_public_key_jwk: sessionPublicJwk,
    session_key_fingerprint: sessionKeyFingerprint
  };

  const bytes = new TextEncoder().encode(canonicalJSONStringifyBrowser(sessionAttestationPayload({ ...attestation, signature: '' })));
  const signature = await crypto.subtle.sign(
    { name: 'ECDSA', hash: 'SHA-256' },
    sessionKeyPair.privateKey,
    bytes
  );
  attestation.signature = bytesToBase64Url(new Uint8Array(signature));

  globalThis.__AML_SESSION_ATTESTATION__ = attestation;
  if (globalThis.document?.dispatchEvent && globalThis.CustomEvent) {
    document.dispatchEvent(new CustomEvent('aml-session-attestation', { detail: attestation }));
  }
  return attestation;
}

export async function verifySessionAttestation({ evidence, challenge, attestation, now = Date.now() } = {}) {
  const checks = {
    receipt_integrity: false,
    evidence_integrity: false,
    challenge_freshness: false,
    challenge_binding: false,
    session_signature: false
  };
  const fail = (reason, extra = {}) => ({ valid: false, reason, checks: { ...checks }, ...extra });
  try {
    const evidenceCheck = await verifyBrowserEvidence(evidence);
    checks.receipt_integrity = evidenceCheck.receipt?.valid === true;
    if (!evidenceCheck.valid) return fail('AML_SESSION_EVIDENCE_INVALID', { evidence: evidenceCheck });
    checks.evidence_integrity = true;
    const challengeCheck = verifyVerificationChallenge(challenge, { now });
    if (!challengeCheck.valid) return fail(challengeCheck.reason);
    checks.challenge_freshness = true;
    assertBrowserJSON(attestation);
    if (!attestation || attestation.schema !== 'aml-session-attestation/1') {
      return fail('AML_SESSION_ATTESTATION_INVALID');
    }
    if (attestation.algorithm !== 'ECDSA-P256-SHA256') {
      return fail('AML_SESSION_ALGORITHM_UNSUPPORTED');
    }
    if (attestation.evidence_hash !== evidence.integrity.value) {
      return fail('AML_SESSION_EVIDENCE_HASH_MISMATCH');
    }
    if (attestation.challenge_nonce !== challenge.nonce || attestation.challenge_expires_at !== challenge.expires_at) {
      return fail('AML_SESSION_CHALLENGE_MISMATCH');
    }
    checks.challenge_binding = true;
    const jwk = attestation.session_public_key_jwk;
    if (!jwk || jwk.kty !== 'EC' || jwk.crv !== 'P-256') {
      return fail('AML_SESSION_KEY_ENCODING_INVALID');
    }
    canonicalBytes(jwk.x, 32, 43, 'AML_SESSION_KEY_ENCODING_INVALID');
    canonicalBytes(jwk.y, 32, 43, 'AML_SESSION_KEY_ENCODING_INVALID');
    const expectedFingerprint = await sha256Browser(attestation.session_public_key_jwk);
    if (expectedFingerprint !== attestation.session_key_fingerprint) {
      return fail('AML_SESSION_KEY_FINGERPRINT_MISMATCH');
    }
    const key = await crypto.subtle.importKey(
      'jwk',
      attestation.session_public_key_jwk,
      { name: 'ECDSA', namedCurve: 'P-256' },
      false,
      ['verify']
    );
    const bytes = new TextEncoder().encode(canonicalJSONStringifyBrowser(sessionAttestationPayload(attestation)));
    const signature = canonicalBytes(attestation.signature, 64, 86,
      'AML_SESSION_SIGNATURE_ENCODING_INVALID');
    const valid = await crypto.subtle.verify(
      { name: 'ECDSA', hash: 'SHA-256' },
      key,
      signature,
      bytes
    );
    checks.session_signature = valid;
    return {
      valid,
      reason: valid ? 'AML_SESSION_ATTESTATION_VALID' : 'AML_SESSION_SIGNATURE_INVALID',
      checks: { ...checks },
      session_key_fingerprint: attestation.session_key_fingerprint,
      evidence_hash: attestation.evidence_hash
    };
  } catch (error) {
    return fail(error?.message || 'AML_SESSION_VERIFY_ERROR');
  }
}

export function resetAMLSessionKey() {
  sessionKeyPair = null;
  sessionPublicJwk = null;
  sessionKeyFingerprint = null;
  globalThis.__AML_SESSION_ATTESTATION__ = null;
}
