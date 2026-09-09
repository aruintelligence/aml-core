#!/usr/bin/env node
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import process from 'node:process';

const resultPath = process.argv[2];
if (!resultPath) {
  console.error('usage: node scripts/verify-verifier-conformance-result.mjs <result.json>');
  process.exit(2);
}

const failures = [];
const sha256 = (bytes) => crypto.createHash('sha256').update(bytes).digest('hex');

let result;
try {
  result = JSON.parse(fs.readFileSync(resultPath, 'utf8'));
} catch (error) {
  console.error(JSON.stringify({ verified: false, failures: [`result JSON unreadable: ${error.message}`] }, null, 2));
  process.exit(1);
}

const challengePath = path.resolve('conformance/verifier-challenge.json');
const vectorPath = path.resolve('independent/python/witness-vector.json');
const challengeBytes = fs.readFileSync(challengePath);
const vectorBytes = fs.readFileSync(vectorPath);
const challenge = JSON.parse(challengeBytes.toString('utf8'));
const expectedChallengeHash = sha256(challengeBytes);
const expectedVectorHash = sha256(vectorBytes);

if (result?.schema !== challenge.result_contract?.schema) failures.push('result schema does not match challenge result contract');
if (result?.challenge_schema !== challenge.schema) failures.push('challenge_schema mismatch');
if (!/^[0-9a-f]{64}$/.test(String(result?.challenge_sha256 || ''))) failures.push('challenge_sha256 must be lowercase SHA-256 hex');
if (!/^[0-9a-f]{64}$/.test(String(result?.witness_vector_sha256 || ''))) failures.push('witness_vector_sha256 must be lowercase SHA-256 hex');
if (result?.challenge_sha256 !== expectedChallengeHash) failures.push('challenge_sha256 does not match exact local challenge bytes');
if (result?.witness_vector_sha256 !== expectedVectorHash) failures.push('witness_vector_sha256 does not match exact local witness-vector bytes');
if (!Array.isArray(result?.results)) failures.push('results must be an array');

const expectedCases = Array.isArray(challenge.cases) ? challenge.cases : [];
if (Array.isArray(result?.results)) {
  if (result.results.length !== expectedCases.length) failures.push('result case count mismatch');
  const seen = new Set();
  for (let i = 0; i < result.results.length; i += 1) {
    const item = result.results[i];
    const expected = expectedCases[i];
    if (!item || typeof item !== 'object' || Array.isArray(item)) {
      failures.push(`results[${i}] must be an object`);
      continue;
    }
    if (seen.has(item.id)) failures.push(`duplicate case id ${item.id}`);
    seen.add(item.id);
    if (!expected || item.id !== expected.id) failures.push(`results[${i}] case id/order mismatch`);
    if (expected && item.expected_valid !== expected.expected_valid) failures.push(`results[${i}] expected_valid mismatch`);
    const observedValid = item?.observed?.valid;
    const exitCode = item?.observed?.exit_code;
    const expectedPassed = expected
      ? observedValid === expected.expected_valid && (expected.expected_valid ? exitCode === 0 : Number.isInteger(exitCode) && exitCode !== 0)
      : false;
    if (item.passed !== expectedPassed) failures.push(`results[${i}] passed flag inconsistent with observed result`);
  }
}

const computedPassed = Array.isArray(result?.results) && result.results.length === expectedCases.length && result.results.every((item) => item?.passed === true);
if (result?.passed !== computedPassed) failures.push('top-level passed flag inconsistent with case results');

const verified = failures.length === 0;
console.log(JSON.stringify({
  verified,
  passed: verified ? result.passed === true : false,
  challenge_sha256: expectedChallengeHash,
  witness_vector_sha256: expectedVectorHash,
  failures,
  claim_boundary: 'Verification proves that this result is structurally consistent with the exact local challenge and witness-vector bytes. It does not prove the tested verifier is independent, trustworthy, secure, or broadly adopted.'
}, null, 2));

process.exit(verified ? 0 : 1);
