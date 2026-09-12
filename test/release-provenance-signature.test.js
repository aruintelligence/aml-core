import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { signReleaseProvenanceEvidence, verifySignedReleaseProvenance } from '../protocol/releaseProvenanceSignature.js';

function evidence() {
  return {
    protocol: 'aml-release-provenance-evidence/1',
    package: 'aml-core',
    version: '1.3.0',
    control_commit: 'a'.repeat(40),
    rollback_target: { version: '1.3.0', git_tag: 'v1.3.0', commit: 'b'.repeat(40) },
    contract_sha256: { 'package.json': 'c'.repeat(64) },
    evidence_root_sha256: 'd'.repeat(64),
    claim_boundary: 'fixture'
  };
}

test('signs provenance and separates signature validity from trust', () => {
  const { privateKey } = crypto.generateKeyPairSync('ed25519');
  const signed = signReleaseProvenanceEvidence(evidence(), privateKey.export({ type: 'pkcs8', format: 'pem' }));
  const untrusted = verifySignedReleaseProvenance(signed);
  assert.equal(untrusted.valid, true);
  assert.equal(untrusted.signature_valid, true);
  assert.equal(untrusted.trusted_key, false);
  const trusted = verifySignedReleaseProvenance(signed, { trusted_fingerprints: [signed.signature.public_key_fingerprint_sha256], require_trusted_key: true });
  assert.equal(trusted.valid, true);
  assert.equal(trusted.trusted_key, true);
});

test('detects provenance tampering', () => {
  const { privateKey } = crypto.generateKeyPairSync('ed25519');
  const signed = signReleaseProvenanceEvidence(evidence(), privateKey.export({ type: 'pkcs8', format: 'pem' }));
  signed.evidence.version = '9.9.9';
  const result = verifySignedReleaseProvenance(signed);
  assert.equal(result.valid, false);
  assert.equal(result.signature_valid, false);
});
