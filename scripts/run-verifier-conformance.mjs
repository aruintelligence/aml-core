#!/usr/bin/env node
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
const challenge = JSON.parse(fs.readFileSync(path.join(repoRoot, 'conformance/verifier-challenge.json'), 'utf8'));
const casesContract = JSON.parse(fs.readFileSync(path.join(repoRoot, challenge.cases_file), 'utf8'));
const vectorPath = path.join(repoRoot, casesContract.bundle_source);
const source = JSON.parse(fs.readFileSync(vectorPath, 'utf8'));
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

if (casesContract.schema !== 'aml-verifier-challenge-cases/1') throw new Error('Unsupported verifier challenge case schema');
if (casesContract.mutation_language?.schema !== 'aml-json-pointer-replace/1') throw new Error('Unsupported verifier challenge mutation language');
if (!Array.isArray(casesContract.cases) || !casesContract.cases.length) throw new Error('Verifier challenge requires cases');

const results = casesContract.cases.map(testCase => {
  const observed = invoke(materializeCase(testCase), testCase.now);
  const passed = observed.valid === testCase.expected_valid && (testCase.expected_valid ? observed.exit_code === 0 : observed.exit_code !== 0);
  return { id: testCase.id, expected_valid: testCase.expected_valid, passed, observed };
});

const passed = results.every(r => r.passed);
console.log(JSON.stringify({
  schema: 'aml-verifier-conformance-result/1',
  prototype: true,
  harness_root: repoRoot,
  challenge_cases: challenge.cases_file,
  command: [command, ...baseArgs],
  passed,
  results,
  claim_boundary: 'PASS is project-defined black-box compatibility evidence, not certification or proof of verifier independence.'
}, null, 2));

process.exit(passed ? 0 : 1);
