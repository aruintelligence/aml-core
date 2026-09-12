import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import { spawnSync } from 'node:child_process';

const sha256 = value => crypto.createHash('sha256').update(value).digest('hex');
const readJson = file => JSON.parse(fs.readFileSync(file, 'utf8'));
const contract = readJson('checkpoint-signing-contract.json');
const vectors = readJson('conformance/checkpoint-succession/vectors.json');

function runNode(script, ...args) {
  const r = spawnSync(process.execPath, [script, ...args], { encoding: 'utf8', shell: false });
  if (r.status !== 0) throw new Error(r.stderr || r.stdout || `${script} failed`);
}
function publicPem(key) { return key.export({ type: 'spki', format: 'pem' }); }
function fingerprint(key) { return sha256(Buffer.from(publicPem(key))); }
function signObject(body, privateKey) { return crypto.sign(null, Buffer.from(JSON.stringify(body)), privateKey).toString('base64'); }
function verifyObject(body, signature, publicKey) { return crypto.verify(null, Buffer.from(JSON.stringify(body)), publicKey, Buffer.from(signature, 'base64')); }
function assert(condition, message) { if (!condition) throw new Error(message); }

assert(contract.signature_algorithm === 'Ed25519', 'Unexpected checkpoint signature algorithm');
assert(contract.trust.verifier_supplied === true, 'Checkpoint trust must be verifier supplied');

const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'aml-checkpoint-witness-'));
const checkpointPath = path.join(temp, 'checkpoint.json');
runNode('scripts/build-release-transparency-checkpoint.mjs', checkpointPath);
const checkpoint = readJson(checkpointPath);
assert(checkpoint.protocol === contract.checkpoint_protocol, 'Checkpoint protocol mismatch');

const signer = crypto.generateKeyPairSync('ed25519');
const attacker = crypto.generateKeyPairSync('ed25519');
const signerId = `test-checkpoint-${fingerprint(signer.publicKey).slice(0, 16)}`;
const signedBody = {
  protocol: contract.signed_checkpoint_protocol,
  checkpoint_sequence: 1,
  previous_checkpoint_root_sha256: null,
  checkpoint_root_sha256: checkpoint.checkpoint_root_sha256,
  checkpoint_sha256: sha256(fs.readFileSync(checkpointPath)),
  signer_id: signerId,
  signer_public_key_pem: publicPem(signer.publicKey),
  claim_boundary: contract.claim_boundary
};
const envelope = { ...signedBody, signature_base64: signObject(signedBody, signer.privateKey) };

function verifyEnvelope(candidate, trustedFingerprints, revoked = new Set(), minimumSequence = 1) {
  const { signature_base64, ...body } = candidate;
  if (body.protocol !== contract.signed_checkpoint_protocol) return false;
  if (body.checkpoint_sequence < minimumSequence) return false;
  const key = crypto.createPublicKey(body.signer_public_key_pem);
  const fp = fingerprint(key);
  if (!verifyObject(body, signature_base64, key)) return false;
  if (!trustedFingerprints.has(fp)) return false;
  if (revoked.has(fp)) return false;
  return true;
}
const signerFp = fingerprint(signer.publicKey);
assert(verifyEnvelope(envelope, new Set([signerFp])) === true, 'Trusted checkpoint signature must verify');
assert(verifyEnvelope(envelope, new Set()) === false, 'Cryptographic validity must not imply trust');
assert(verifyEnvelope(envelope, new Set([signerFp]), new Set([signerFp])) === false, 'Revoked signer must fail');
const forged = { ...envelope, checkpoint_root_sha256: '0'.repeat(64) };
assert(verifyEnvelope(forged, new Set([signerFp])) === false, 'Tampered checkpoint envelope must fail');
const attackerBody = { ...signedBody, signer_id: 'test-attacker', signer_public_key_pem: publicPem(attacker.publicKey) };
const attackerEnvelope = { ...attackerBody, signature_base64: signObject(attackerBody, attacker.privateKey) };
assert(verifyEnvelope(attackerEnvelope, new Set([signerFp])) === false, 'Untrusted valid signer must fail');

function successionAccept(v) {
  if (v.prior_sequence === 0) return v.candidate_sequence === 1 && v.prior_root === null && v.candidate_previous_root === null;
  return v.candidate_sequence === v.prior_sequence + 1 && v.candidate_previous_root === v.prior_root;
}
for (const v of vectors.vectors) assert(successionAccept(v) === v.accept, `Succession vector failed: ${v.id}`);

const witness = crypto.generateKeyPairSync('ed25519');
const witnessId = `test-witness-${fingerprint(witness.publicKey).slice(0, 16)}`;
const receiptBody = {
  protocol: contract.witness_receipt_protocol,
  checkpoint_root_sha256: envelope.checkpoint_root_sha256,
  checkpoint_sequence: envelope.checkpoint_sequence,
  witness_id: witnessId,
  witness_public_key_pem: publicPem(witness.publicKey),
  observation: 'synthetic_ci_reproduction',
  claim_boundary: contract.claim_boundary
};
const receipt = { ...receiptBody, signature_base64: signObject(receiptBody, witness.privateKey) };
const witnessFp = fingerprint(witness.publicKey);
function verifyWitness(candidate, trustedFingerprints) {
  const { signature_base64, ...body } = candidate;
  const key = crypto.createPublicKey(body.witness_public_key_pem);
  return body.protocol === contract.witness_receipt_protocol &&
    body.checkpoint_root_sha256 === envelope.checkpoint_root_sha256 &&
    body.checkpoint_sequence === envelope.checkpoint_sequence &&
    verifyObject(body, signature_base64, key) &&
    trustedFingerprints.has(fingerprint(key));
}
assert(verifyWitness(receipt, new Set([witnessFp])) === true, 'Trusted witness receipt must verify');
assert(verifyWitness(receipt, new Set()) === false, 'Witness signature validity must remain separate from trust');
assert(verifyWitness({ ...receipt, checkpoint_sequence: 2 }, new Set([witnessFp])) === false, 'Witness receipt sequence tamper must fail');
assert(verifyEnvelope({ ...envelope, checkpoint_sequence: 0 }, new Set([signerFp]), new Set(), 1) === false, 'Checkpoint rollback below verifier minimum must fail');

const report = {
  protocol: 'aml-checkpoint-witness-control-plane-report/1',
  checkpoint_root_sha256: checkpoint.checkpoint_root_sha256,
  signed_checkpoint: {
    cryptographic_signature_verified: true,
    verifier_supplied_trust_verified: true,
    untrusted_valid_signature_rejected: true,
    revoked_signer_rejected: true,
    tamper_rejected: true
  },
  succession: {
    vectors_checked: vectors.vectors.length,
    anti_fork_verified: true,
    anti_rollback_verified: true
  },
  witness_receipt: {
    cryptographic_signature_verified: true,
    verifier_supplied_trust_verified: true,
    trust_separation_verified: true,
    tamper_rejected: true,
    synthetic_only: true
  },
  production_private_key_used: false,
  claim_boundary: contract.claim_boundary,
  passed: true
};
console.log(JSON.stringify(report, null, 2));
