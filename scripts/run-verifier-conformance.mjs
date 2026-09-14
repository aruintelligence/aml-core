#!/usr/bin/env node
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';

const split = process.argv.indexOf('--');
if (split < 0 || split === process.argv.length - 1) {
  console.error('usage: node scripts/run-verifier-conformance.mjs -- <verifier-command> [args...]');
  process.exit(2);
}

const command = process.argv[split + 1];
const baseArgs = process.argv.slice(split + 2);
const scriptDir = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(scriptDir, '..');
const challengePath = path.join(repoRoot, 'conformance/verifier-challenge.json');
const challengeBytes = fs.readFileSync(challengePath);
const challenge = JSON.parse(challengeBytes.toString('utf8'));
if (typeof challenge.cases_file !== 'string' || !challenge.cases_file) throw new Error('Verifier challenge must declare cases_file');

const casesPath = path.join(repoRoot, challenge.cases_file);
const casesBytes = fs.readFileSync(casesPath);
const casesContract = JSON.parse(casesBytes.toString('utf8'));
if (casesContract.schema !== 'aml-verifier-challenge-cases/1') throw new Error('Unsupported verifier challenge case schema');
if (casesContract.mutation_language?.schema !== 'aml-json-pointer-replace/1') throw new Error('Unsupported verifier challenge mutation language');
if (!Array.isArray(casesContract.cases) || !casesContract.cases.length) throw new Error('Verifier challenge requires cases');
if (typeof casesContract.bundle_source !== 'string' || !casesContract.bundle_source) throw new Error('Verifier challenge cases require bundle_source');
if (challenge.witness_vector !== casesContract.bundle_source) throw new Error('Challenge witness_vector and cases bundle_source must match');

const vectorPath = path.join(repoRoot, casesContract.bundle_source);
const vectorBytes = fs.readFileSync(vectorPath);
const source = JSON.parse(vectorBytes.toString('utf8'));
const sha256 = (bytes) => crypto.createHash('sha256').update(bytes).digest('hex');
const challengeSha256 = sha256(challengeBytes);
const challengeCasesSha256 = sha256(casesBytes);
const witnessVectorSha256 = sha256(vectorBytes);
const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'aml-verifier-conformance-'));

function invoke(bundlePath, now) {
  const result = spawnSync(command, [...baseArgs, '--now', now, bundlePath], {
    encoding: 'utf8',
    cwd: process.cwd()
  });
  let parsed = null;
  try { parsed = JSON.parse((result.stdout || '').trim()); } catch {}
  return {
    exit_code: result.status,
    valid: parsed?.valid,
    reason: parsed?.reason || null,
    stdout: (result.stdout || '').trim(),
    stderr: (result.stderr || '').trim()
  };
}

function write(name, value) {
  const target = path.join(temp, `${name}.json`);
  fs.writeFileSync(target, JSON.stringify(value, null, 2));
  return target;
}

function decodePointerToken(token) {
  return token.replace(/~1/g, '/').replace(/~0/g, '~');
}

function applyReplace(root, mutation) {
  if (!mutation || mutation.op !== 'replace' || typeof mutation.path !== 'string' || !mutation.path.startsWith('/')) {
    throw new Error('Unsupported verifier challenge mutation');
  }
  const tokens = mutation.path.slice(1).split('/').map(decodePointerToken);
  let parent = root;
  for (const token of tokens.slice(0, -1)) {
    if (parent === null || typeof parent !== 'object' || !(token in parent)) throw new Error(`Mutation path does not exist: ${mutation.path}`);
    parent = parent[token];
  }
  const leaf = tokens.at(-1);
  if (parent === null || typeof parent !== 'object' || !(leaf in parent)) throw new Error(`Mutation path does not exist: ${mutation.path}`);
  parent[leaf] = structuredClone(mutation.value);
}

function materializeCase(testCase) {
  const bundle = structuredClone(source);
  for (const mutation of testCase.mutations || []) applyReplace(bundle, mutation);
  if (!(testCase.mutations || []).length) return vectorPath;
  return write(testCase.id, bundle);
}

const results = casesContract.cases.map(testCase => {
  const observed = invoke(materializeCase(testCase), testCase.now);
  const passed = observed.valid === testCase.expected_valid && (testCase.expected_valid ? observed.exit_code === 0 : observed.exit_code !== 0);
  return { id: testCase.id, expected_valid: testCase.expected_valid, passed, observed };
});

const passed = results.every(r => r.passed);
console.log(JSON.stringify({
  schema: challenge.result_contract?.schema || 'aml-verifier-conformance-result/1',
  prototype: true,
  challenge_schema: challenge.schema,
  challenge_sha256: challengeSha256,
  witness_vector_sha256: witnessVectorSha256,
  challenge_cases: challenge.cases_file,
  challenge_cases_sha256: challengeCasesSha256,
  harness_root: repoRoot,
  command: [command, ...baseArgs],
  passed,
  results,
  claim_boundary: 'PASS is project-defined black-box compatibility evidence bound to the exact published challenge, language-neutral case corpus, and witness-vector bytes; it is not certification or proof of verifier independence.'
}, null, 2));

process.exit(passed ? 0 : 1);
