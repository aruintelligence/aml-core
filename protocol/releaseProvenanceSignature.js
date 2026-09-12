import crypto from 'node:crypto';
import { canonicalJSONStringify } from './canonicalJson.js';

export const AML_RELEASE_PROVENANCE_EVIDENCE = 'aml-release-provenance-evidence/1';
export const AML_SIGNED_RELEASE_PROVENANCE = 'aml-signed-release-provenance/1';
export const AML_SIGNED_RELEASE_PROVENANCE_VERIFICATION = 'aml-signed-release-provenance-verification/1';

function material(evidence) {
  if (!evidence || evidence.protocol !== AML_RELEASE_PROVENANCE_EVIDENCE) {
    throw new Error('aml-release-provenance-evidence/1 object required');
  }
  if (!/^[a-f0-9]{64}$/.test(evidence.evidence_root_sha256 || '')) {
    throw new Error('release provenance evidence root must be SHA-256');
  }
  return Buffer.from(canonicalJSONStringify(evidence), 'utf8');
}

function fingerprint(publicKeyPem) {
  const key = crypto.createPublicKey(publicKeyPem);
  const der = key.export({ type: 'spki', format: 'der' });
  return crypto.createHash('sha256').update(der).digest('hex');
}

export function signReleaseProvenanceEvidence(evidence, privateKeyPem, options = {}) {
  const privateKey = crypto.createPrivateKey(privateKeyPem);
  if (privateKey.asymmetricKeyType !== 'ed25519') throw new Error('release provenance signing requires Ed25519');
  const publicKeyPem = crypto.createPublicKey(privateKey).export({ type: 'spki', format: 'pem' }).toString();
  const fp = fingerprint(publicKeyPem);
  return {
    protocol: AML_SIGNED_RELEASE_PROVENANCE,
    evidence: structuredClone(evidence),
    signature: {
      algorithm: 'Ed25519',
      key_id: options.key_id || `sha256:${fp}`,
      public_key_fingerprint_sha256: fp,
      public_key_pem: publicKeyPem,
      signature_base64: crypto.sign(null, material(evidence), privateKey).toString('base64'),
      signer: options.signer || null,
      scope: options.scope || 'release-provenance-integrity'
    }
  };
}

export function verifySignedReleaseProvenance(signed, options = {}) {
  const errors = [];
  if (!signed || signed.protocol !== AML_SIGNED_RELEASE_PROVENANCE) {
    return { protocol: AML_SIGNED_RELEASE_PROVENANCE_VERIFICATION, valid: false, signature_valid: false, trusted_key: false, errors: ['unsupported signed release provenance protocol'] };
  }
  const sig = signed.signature || {};
  let signatureValid = false;
  let fp = null;
  try {
    if (sig.algorithm !== 'Ed25519') throw new Error('signature algorithm must be Ed25519');
    fp = fingerprint(sig.public_key_pem);
    if (fp !== sig.public_key_fingerprint_sha256) throw new Error('public key fingerprint mismatch');
    signatureValid = crypto.verify(null, material(signed.evidence), crypto.createPublicKey(sig.public_key_pem), Buffer.from(sig.signature_base64, 'base64'));
    if (!signatureValid) errors.push('Ed25519 signature verification failed');
  } catch (error) {
    errors.push(error.message || String(error));
  }
  const trusted = new Set(options.trusted_fingerprints || []);
  const trustedKey = fp != null && trusted.has(fp);
  if (options.require_trusted_key === true && !trustedKey) errors.push('signing key is not in supplied trust set');
  return {
    protocol: AML_SIGNED_RELEASE_PROVENANCE_VERIFICATION,
    valid: signatureValid && errors.length === 0,
    signature_valid: signatureValid,
    trusted_key: trustedKey,
    public_key_fingerprint_sha256: fp,
    key_id: sig.key_id || null,
    signer: sig.signer || null,
    scope: sig.scope || null,
    evidence_root_sha256: signed.evidence?.evidence_root_sha256 || null,
    errors
  };
}
