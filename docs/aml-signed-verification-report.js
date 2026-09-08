// ĀML signed verification reports — SHIPPED reference prototype.
// Binds one aml-verification-report/1 to a P-256 verifier key.
// Key possession does not prove verifier identity, independence, certification authority, or correctness.

import { canonicalJSONStringifyBrowser, sha256Browser } from './aml-browser-integrity.js';

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

export async function createVerifierKeyPair() {
  if (!globalThis.crypto?.subtle) throw new Error('AML_VERIFIER_CRYPTO_UNAVAILABLE');
  return crypto.subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-256' },
    true,
    ['sign', 'verify']
  );
}

export async function signVerificationReport(report, keyPair) {
  if (!report || report.schema !== 'aml-verification-report/1') throw new Error('AML_SIGNED_REPORT_INVALID_REPORT');
  if (!keyPair?.privateKey || !keyPair?.publicKey) throw new Error('AML_SIGNED_REPORT_KEYPAIR_REQUIRED');

  const publicJwk = await crypto.subtle.exportKey('jwk', keyPair.publicKey);
  const fingerprint = await sha256Browser(publicJwk);
  const bytes = new TextEncoder().encode(canonicalJSONStringifyBrowser(report));
  const signature = await crypto.subtle.sign(
    { name: 'ECDSA', hash: 'SHA-256' },
    keyPair.privateKey,
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
    if (!envelope || envelope.schema !== 'aml-signed-verification-report/1') {
      return { valid: false, reason: 'AML_SIGNED_REPORT_INVALID' };
    }
    if (envelope.algorithm !== 'ECDSA-P256-SHA256') {
      return { valid: false, reason: 'AML_SIGNED_REPORT_ALGORITHM_UNSUPPORTED' };
    }
    if (envelope.report?.schema !== 'aml-verification-report/1') {
      return { valid: false, reason: 'AML_SIGNED_REPORT_REPORT_INVALID' };
    }
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
    const valid = await crypto.subtle.verify(
      { name: 'ECDSA', hash: 'SHA-256' },
      publicKey,
      base64UrlToBytes(envelope.signature),
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
