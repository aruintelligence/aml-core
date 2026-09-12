#!/usr/bin/env node
import fs from 'node:fs';
import crypto from 'node:crypto';

const contract = JSON.parse(fs.readFileSync(new URL('../../external-witness-submission-contract.json', import.meta.url), 'utf8'));
const sha256 = value => crypto.createHash('sha256').update(value).digest('hex');

function canonical(value) {
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  if (value && typeof value === 'object') {
    return `{${Object.keys(value).sort().map(k => `${JSON.stringify(k)}:${canonical(value[k])}`).join(',')}}`;
  }
  return JSON.stringify(value);
}

function fail(message) {
  console.error(message);
  process.exit(1);
}

function validateSubmission(s) {
  if (!s || s.protocol !== contract.submission_protocol) fail('Invalid submission protocol');
  for (const field of contract.required_submission_fields) if (!(field in s)) fail(`Missing submission field: ${field}`);
  if (!contract.results.includes(s.result)) fail('Result must be PASS, FAIL, or MIXED');
  if (!s.subject || typeof s.subject.repository !== 'string') fail('subject.repository is required');
  if (!new RegExp(contract.subject.commit_sha_pattern).test(s.subject.commit_sha || '')) fail('subject.commit_sha must be 40 lowercase hex characters');
  if (!s.reproduction || typeof s.reproduction.command !== 'string' || !s.reproduction.command.trim()) fail('reproduction.command is required');
  if (!Array.isArray(s.evidence) || s.evidence.length < contract.evidence.minimum_items) fail('At least one evidence item is required');
  for (const [i, item] of s.evidence.entries()) {
    for (const field of contract.evidence.required_fields) if (!(field in item)) fail(`Evidence ${i} missing field: ${field}`);
    if (!new RegExp(contract.evidence.sha256_pattern).test(item.sha256 || '')) fail(`Evidence ${i} sha256 must be 64 lowercase hex characters`);
  }
  if (typeof s.claim_boundary !== 'string' || !s.claim_boundary.trim()) fail('claim_boundary is required');
  return true;
}

function verifySigned(envelope) {
  if (!envelope || envelope.protocol !== contract.signed_submission_protocol) fail('Invalid signed submission protocol');
  validateSubmission(envelope.submission);
  if (!envelope.witness_public_key_pem || !envelope.witness_key_fingerprint_sha256 || !envelope.signature_base64) fail('Signed submission is incomplete');
  const publicKey = crypto.createPublicKey(envelope.witness_public_key_pem);
  const pem = publicKey.export({ type: 'spki', format: 'pem' });
  const fingerprint = sha256(Buffer.from(pem));
  if (fingerprint !== envelope.witness_key_fingerprint_sha256) fail('Witness key fingerprint mismatch');
  const bytes = Buffer.from(canonical(envelope.submission));
  if (!crypto.verify(null, bytes, publicKey, Buffer.from(envelope.signature_base64, 'base64'))) fail('Witness signature verification failed');
  return fingerprint;
}

const [command, ...args] = process.argv.slice(2);
if (command === 'template') {
  const [repository, commitSha, result = 'PASS'] = args;
  if (!repository || !commitSha) fail('Usage: template <owner/repo> <40-char-commit-sha> [PASS|FAIL|MIXED]');
  const template = {
    protocol: contract.submission_protocol,
    subject: { repository, commit_sha: commitSha },
    result,
    reproduction: { command: 'REPLACE_WITH_EXACT_COMMAND', environment: 'REPLACE_WITH_ENVIRONMENT' },
    evidence: [{ type: 'REPLACE_WITH_EVIDENCE_TYPE', sha256: '0'.repeat(64), description: 'REPLACE_WITH_EVIDENCE_DESCRIPTION' }],
    notes: 'Replace placeholders before signing or publishing.',
    claim_boundary: contract.claim_boundary
  };
  process.stdout.write(`${JSON.stringify(template, null, 2)}\n`);
} else if (command === 'sign') {
  const [submissionPath, privateKeyPath, outputPath] = args;
  if (!submissionPath || !privateKeyPath || !outputPath) fail('Usage: sign <submission.json> <ed25519-private-key.pem> <signed-output.json>');
  const submission = JSON.parse(fs.readFileSync(submissionPath, 'utf8'));
  validateSubmission(submission);
  const privateKey = crypto.createPrivateKey(fs.readFileSync(privateKeyPath, 'utf8'));
  if (privateKey.asymmetricKeyType !== 'ed25519') fail('Signing key must be Ed25519');
  const publicKey = crypto.createPublicKey(privateKey);
  const pem = publicKey.export({ type: 'spki', format: 'pem' });
  const fingerprint = sha256(Buffer.from(pem));
  const signature = crypto.sign(null, Buffer.from(canonical(submission)), privateKey).toString('base64');
  const envelope = {
    protocol: contract.signed_submission_protocol,
    submission,
    witness_public_key_pem: pem,
    witness_key_fingerprint_sha256: fingerprint,
    signature_base64: signature,
    trust_established: false,
    independence_established: false,
    claim_boundary: contract.claim_boundary
  };
  fs.writeFileSync(outputPath, `${JSON.stringify(envelope, null, 2)}\n`);
  process.stdout.write(`${JSON.stringify({ signed: true, output: outputPath, witness_key_fingerprint_sha256: fingerprint }, null, 2)}\n`);
} else if (command === 'verify') {
  const [path] = args;
  if (!path) fail('Usage: verify <submission-or-signed-submission.json>');
  const value = JSON.parse(fs.readFileSync(path, 'utf8'));
  if (value.protocol === contract.submission_protocol) {
    validateSubmission(value);
    process.stdout.write(`${JSON.stringify({ valid: true, signed: false, trust_established: false, independence_established: false, result: value.result }, null, 2)}\n`);
  } else {
    const fingerprint = verifySigned(value);
    process.stdout.write(`${JSON.stringify({ valid: true, signed: true, cryptographic_signature_verified: true, witness_key_fingerprint_sha256: fingerprint, trust_established: false, independence_established: false, result: value.submission.result }, null, 2)}\n`);
  }
} else {
  console.log('aml-external-witness');
  console.log('  template <owner/repo> <commit-sha> [PASS|FAIL|MIXED]');
  console.log('  sign <submission.json> <ed25519-private-key.pem> <signed-output.json>');
  console.log('  verify <submission-or-signed-submission.json>');
  console.log('Never submit private keys or secrets. Signature validity is separate from trust and independence.');
}
