// ĀML signed verification reports — SHIPPED reference prototype.
// Binds one aml-verification-report/1 to a P-256 verifier key.
// Key possession does not prove verifier identity, independence, certification authority, or correctness.

import { canonicalJSONStringifyBrowser, sha256Browser,
  snapshotBrowserJSON } from './aml-browser-integrity.js';

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

// Web Crypto verifies decoded bytes, while other runtimes may reject alternate
// text spellings. A raw P-256 ECDSA signature is exactly 64 bytes and has one
// unpadded base64url encoding of 86 characters.
function canonicalSignatureBytes(value) {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_-]{86}$/.test(value)) {
    throw new Error('AML_SIGNED_REPORT_SIGNATURE_ENCODING_INVALID');
  }
  const bytes = base64UrlToBytes(value);
  if (bytes.length !== 64 || bytesToBase64Url(bytes) !== value) {
    throw new Error('AML_SIGNED_REPORT_SIGNATURE_ENCODING_INVALID');
  }
  return bytes;
}

// P-256 coordinates must each be exactly 32 bytes in one unpadded base64url
// spelling. Web Crypto may import alternate encodings of the same point;
// rejecting them keeps the key document unambiguous across runtimes.
export function assertCanonicalVerifierPublicKey(jwk) {
  if (!jwk || typeof jwk !== 'object' || Array.isArray(jwk) ||
      jwk.kty !== 'EC' || jwk.crv !== 'P-256') {
    throw new Error('AML_SIGNED_REPORT_KEY_ENCODING_INVALID');
  }
  for (const coordinate of [jwk.x, jwk.y]) {
    if (typeof coordinate !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(coordinate)) {
      throw new Error('AML_SIGNED_REPORT_KEY_ENCODING_INVALID');
    }
    const bytes = base64UrlToBytes(coordinate);
    if (bytes.length !== 32 || bytesToBase64Url(bytes) !== coordinate) {
      throw new Error('AML_SIGNED_REPORT_KEY_ENCODING_INVALID');
    }
  }
}

export async function createVerifierKeyPair() {
  if (!globalThis.crypto?.subtle) throw new Error('AML_VERIFIER_CRYPTO_UNAVAILABLE');
  return crypto.subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-256' },
    true,
    ['sign', 'verify']
  );
}

export async function signVerificationReport(report, keyPair) {
  report = snapshotBrowserJSON(report);
  if (!report || report.schema !== 'aml-verification-report/1') throw new Error('AML_SIGNED_REPORT_INVALID_REPORT');
  if (!keyPair?.privateKey || !keyPair?.publicKey) throw new Error('AML_SIGNED_REPORT_KEYPAIR_REQUIRED');

  const { privateKey, publicKey } = keyPair;

  const publicJwk = await crypto.subtle.exportKey('jwk', publicKey);
  const fingerprint = await sha256Browser(publicJwk);
  const bytes = new TextEncoder().encode(canonicalJSONStringifyBrowser(report));
  const signature = await crypto.subtle.sign(
    { name: 'ECDSA', hash: 'SHA-256' },
    privateKey,
    bytes
  );

  return {
    schema: 'aml-signed-verification-report/1',
    prototype: true,
    algorithm: 'ECDSA-P256-SHA256',
    report,
    verifier_public_key_jwk: publicJwk,
    verifier_key_fingerprint: fingerprint,
    signature: bytesToBase64Url(new Uint8Array(signature))
  };
}

export async function verifySignedVerificationReport(envelope) {
  try {
    envelope = snapshotBrowserJSON(envelope);
    if (!envelope || envelope.schema !== 'aml-signed-verification-report/1') {
      return { valid: false, reason: 'AML_SIGNED_REPORT_INVALID' };
    }
    if (envelope.algorithm !== 'ECDSA-P256-SHA256') {
      return { valid: false, reason: 'AML_SIGNED_REPORT_ALGORITHM_UNSUPPORTED' };
    }
    if (envelope.report?.schema !== 'aml-verification-report/1') {
      return { valid: false, reason: 'AML_SIGNED_REPORT_REPORT_INVALID' };
    }
    assertCanonicalVerifierPublicKey(envelope.verifier_public_key_jwk);
    const expectedFingerprint = await sha256Browser(envelope.verifier_public_key_jwk);
    if (expectedFingerprint !== envelope.verifier_key_fingerprint) {
      return { valid: false, reason: 'AML_SIGNED_REPORT_KEY_FINGERPRINT_MISMATCH' };
    }
    const publicKey = await crypto.subtle.importKey(
      'jwk',
      envelope.verifier_public_key_jwk,
      { name: 'ECDSA', namedCurve: 'P-256' },
      false,
      ['verify']
    );
    const bytes = new TextEncoder().encode(canonicalJSONStringifyBrowser(envelope.report));
    const signature = canonicalSignatureBytes(envelope.signature);
    const valid = await crypto.subtle.verify(
      { name: 'ECDSA', hash: 'SHA-256' },
      publicKey,
      signature,
      bytes
    );
    return {
      valid,
      reason: valid ? 'AML_SIGNED_REPORT_VALID' : 'AML_SIGNED_REPORT_SIGNATURE_INVALID',
      verifier_key_fingerprint: envelope.verifier_key_fingerprint,
      verifier: envelope.report.verifier,
      artifact_hash: envelope.report.artifact_hash
    };
  } catch (error) {
    return { valid: false, reason: error?.message || 'AML_SIGNED_REPORT_VERIFY_ERROR' };
  }
}
