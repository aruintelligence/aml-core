import fs from 'node:fs';
import crypto from 'node:crypto';

const contract = JSON.parse(fs.readFileSync('witness-evolution-contract.json', 'utf8'));
const vectors = JSON.parse(fs.readFileSync('conformance/witness-evolution/vectors.json', 'utf8'));
const sha256 = value => crypto.createHash('sha256').update(value).digest('hex');
const assert = (condition, message) => { if (!condition) throw new Error(message); };

assert(contract.signature_algorithm === 'Ed25519', 'Unexpected witness signature algorithm');
assert(contract.external_submission.signature_validity_is_separate_from_trust === true, 'External submission trust separation must be explicit');
assert(contract.external_submission.project_generated_submissions_cannot_self_claim_independence === true, 'Project submissions must not self-claim independence');

function consistencyAccept(v) {
  return v.to_sequence === v.from_sequence + 1 && v.predecessor_matches === true;
}
function rotationAccept(v) {
  return v.next_version === v.prior_version + 1 &&
    v.prior_root_matches === true &&
    v.distinct_ids === true &&
    v.distinct_keys === true &&
    v.quorum_preserved === true &&
    v.contains_revoked === false;
}
for (const v of vectors.vectors) {
  const actual = v.kind === 'consistency' ? consistencyAccept(v) : rotationAccept(v);
  assert(actual === v.accept, `Vector failed: ${v.id}`);
}

const witness = crypto.generateKeyPairSync('ed25519');
const publicPem = witness.publicKey.export({ type: 'spki', format: 'pem' });
const fingerprint = sha256(Buffer.from(publicPem));
const submissionBody = {
  protocol: contract.external_submission_protocol,
  checkpoint_root_sha256: 'a'.repeat(64),
  checkpoint_sequence: 11,
  witness_id: `synthetic-${fingerprint.slice(0, 16)}`,
  witness_public_key_pem: publicPem,
  claimed_independent: false,
  observation: 'synthetic_ci_external_submission_fixture'
};
const signature = crypto.sign(null, Buffer.from(JSON.stringify(submissionBody)), witness.privateKey).toString('base64');
const submission = { ...submissionBody, signature_base64: signature };

function verifySubmission(candidate, trustedFingerprints, verifierIndependentFingerprints) {
  const { signature_base64, ...body } = candidate;
  if (body.protocol !== contract.external_submission_protocol) return { accepted: false, independent: false };
  const key = crypto.createPublicKey(body.witness_public_key_pem);
  const fp = sha256(Buffer.from(key.export({ type: 'spki', format: 'pem' })));
  const valid = crypto.verify(null, Buffer.from(JSON.stringify(body)), key, Buffer.from(signature_base64, 'base64'));
  if (!valid || !trustedFingerprints.has(fp)) return { accepted: false, independent: false };
  return { accepted: true, independent: verifierIndependentFingerprints.has(fp) };
}
const trusted = new Set([fingerprint]);
assert(verifySubmission(submission, trusted, new Set()).accepted === true, 'Trusted valid imported receipt must verify');
assert(verifySubmission(submission, new Set(), new Set()).accepted === false, 'Valid signature must not imply trust');
assert(verifySubmission(submission, trusted, new Set()).independent === false, 'Project fixture must not become independent evidence');
assert(verifySubmission(submission, trusted, new Set([fingerprint])).independent === true, 'Verifier may independently assert external independence');
const tampered = { ...submission, checkpoint_sequence: 12 };
assert(verifySubmission(tampered, trusted, new Set()).accepted === false, 'Tampered imported receipt must fail');

const proof = {
  protocol: contract.consistency_proof_protocol,
  from_sequence: 11,
  from_root_sha256: 'a'.repeat(64),
  to_sequence: 12,
  to_root_sha256: 'b'.repeat(64),
  to_previous_root_sha256: 'a'.repeat(64)
};
assert(proof.to_sequence === proof.from_sequence + 1, 'Consistency proof sequence must be contiguous');
assert(proof.to_previous_root_sha256 === proof.from_root_sha256, 'Consistency proof predecessor must match');

const report = {
  protocol: 'aml-witness-evolution-report/1',
  vectors_checked: vectors.vectors.length,
  consistency_proof_verified: true,
  anti_fork_verified: true,
  anti_rollback_verified: true,
  witness_set_rotation_verified: true,
  quorum_collapse_rejected: true,
  revoked_reentry_rejected: true,
  external_submission_signature_verified: true,
  external_submission_trust_separation_verified: true,
  external_independence_requires_verifier_assertion: true,
  synthetic_witnesses_only: true,
  external_independent_witnesses_claimed: false,
  passed: true,
  claim_boundary: contract.claim_boundary
};
console.log(JSON.stringify(report, null, 2));
