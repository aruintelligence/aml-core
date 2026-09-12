import fs from 'node:fs';
import crypto from 'node:crypto';
import { spawnSync } from 'node:child_process';

function fail(message) { throw new Error(message); }
function read(file) { return JSON.parse(fs.readFileSync(file, 'utf8')); }
function fingerprint(publicKeyPem) {
  const der = crypto.createPublicKey(publicKeyPem).export({ type: 'spki', format: 'der' });
  return crypto.createHash('sha256').update(der).digest('hex');
}
function material(evidence, sequence) {
  return Buffer.from(JSON.stringify({ protocol: evidence.protocol, evidence_root_sha256: evidence.evidence_root_sha256, control_commit: evidence.control_commit, release_sequence: sequence }), 'utf8');
}
function sign(evidence, sequence, privateKey) {
  const publicKey = crypto.createPublicKey(privateKey).export({ type: 'spki', format: 'pem' }).toString();
  return {
    algorithm: 'Ed25519',
    public_key_pem: publicKey,
    public_key_fingerprint_sha256: fingerprint(publicKey),
    signature_base64: crypto.sign(null, material(evidence, sequence), privateKey).toString('base64')
  };
}
function verifyEnvelope(envelope, policy, options = {}) {
  const errors = [];
  const trusted = new Set(options.trusted_fingerprints || []);
  const revoked = new Set(options.revoked_fingerprints || []);
  const minimumSequence = Number(options.minimum_release_sequence ?? 0);
  if (envelope.release_sequence < minimumSequence) errors.push('release sequence is below verifier minimum');
  const accepted = new Set();
  for (const sig of envelope.signatures || []) {
    try {
      if (sig.algorithm !== policy.signature_algorithm) throw new Error('unsupported signature algorithm');
      const fp = fingerprint(sig.public_key_pem);
      if (fp !== sig.public_key_fingerprint_sha256) throw new Error('fingerprint mismatch');
      if (revoked.has(fp)) continue;
      const ok = crypto.verify(null, material(envelope.evidence, envelope.release_sequence), crypto.createPublicKey(sig.public_key_pem), Buffer.from(sig.signature_base64, 'base64'));
      if (ok && trusted.has(fp)) accepted.add(fp);
    } catch (error) { errors.push(error.message || String(error)); }
  }
  if (accepted.size < policy.authorization.production_threshold) errors.push('trusted signature threshold not met');
  return { valid: errors.length === 0, trusted_distinct_signers: accepted.size, errors };
}

const policy = read('release-signing-policy.json');
if (policy.protocol !== 'aml-release-signing-policy/1') fail('Unexpected release signing policy protocol');
const build = spawnSync(process.execPath, ['scripts/build-release-provenance-evidence.mjs', 'aml-release-provenance-evidence.json'], { encoding: 'utf8' });
if (build.status !== 0) fail(build.stderr || build.stdout || 'failed to build provenance evidence');
const evidence = read('aml-release-provenance-evidence.json');
const sequence = policy.freshness.current_release_sequence;
const keys = Array.from({ length: 3 }, () => crypto.generateKeyPairSync('ed25519'));
const signatures = keys.map(k => sign(evidence, sequence, k.privateKey));
const trust = signatures.map(s => s.public_key_fingerprint_sha256);
const envelope = { protocol: 'aml-threshold-signed-release-provenance/1', release_sequence: sequence, evidence, signatures: signatures.slice(0, 2) };

const twoOfThree = verifyEnvelope(envelope, policy, { trusted_fingerprints: trust, minimum_release_sequence: sequence });
if (!twoOfThree.valid || twoOfThree.trusted_distinct_signers !== 2) fail('2-of-N threshold should pass');
const oneOfThree = verifyEnvelope({ ...envelope, signatures: signatures.slice(0, 1) }, policy, { trusted_fingerprints: trust, minimum_release_sequence: sequence });
if (oneOfThree.valid) fail('single signature must not satisfy production threshold');
const duplicate = verifyEnvelope({ ...envelope, signatures: [signatures[0], signatures[0]] }, policy, { trusted_fingerprints: trust, minimum_release_sequence: sequence });
if (duplicate.valid) fail('duplicate key must not inflate threshold');
const revoked = verifyEnvelope(envelope, policy, { trusted_fingerprints: trust, revoked_fingerprints: [signatures[1].public_key_fingerprint_sha256], minimum_release_sequence: sequence });
if (revoked.valid) fail('revoked signer must not count toward threshold');
const stale = verifyEnvelope(envelope, policy, { trusted_fingerprints: trust, minimum_release_sequence: sequence + 1 });
if (stale.valid) fail('anti-rollback sequence check must reject stale evidence');
const tampered = structuredClone(envelope);
tampered.evidence.evidence_root_sha256 = '0'.repeat(64);
const tamperResult = verifyEnvelope(tampered, policy, { trusted_fingerprints: trust, minimum_release_sequence: sequence });
if (tamperResult.valid) fail('tampered evidence must fail signature verification');

console.log(JSON.stringify({
  valid: true,
  protocol: 'aml-release-provenance-quorum-verification/1',
  threshold: policy.authorization.production_threshold,
  tested: ['2-of-N pass','1-of-N reject','duplicate signer reject','revoked signer reject','stale sequence reject','tamper reject'],
  claim_boundary: 'Generated test keys only. This verifies project-controlled threshold, revocation, freshness, and tamper behavior; it is not an official ARU signature or external attestation.'
}, null, 2));
