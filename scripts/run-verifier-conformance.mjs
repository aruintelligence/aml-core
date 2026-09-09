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
const vectorPath = path.join(repoRoot, 'independent/python/witness-vector.json');
const challengeBytes = fs.readFileSync(challengePath);
const vectorBytes = fs.readFileSync(vectorPath);
const challenge = JSON.parse(challengeBytes.toString('utf8'));
const source = JSON.parse(vectorBytes.toString('utf8'));
const sha256 = (bytes) => crypto.createHash('sha256').update(bytes).digest('hex');
const challengeSha256 = sha256(challengeBytes);
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

const purposeTamper = structuredClone(source);
purposeTamper.evidence.receipt.decisions[0].purpose = 'tampered-by-conformance-harness';

const challengeTamper = structuredClone(source);
challengeTamper.challenge.nonce = 'tampered-challenge-nonce-000000000000000000000';

const cases = [
  {
    id: 'golden-valid',
    expected: true,
    run: () => invoke(vectorPath, '2030-01-01T00:05:00Z')
  },
  {
    id: 'tampered-purpose',
    expected: false,
    run: () => invoke(write('tampered-purpose', purposeTamper), '2030-01-01T00:05:00Z')
  },
  {
    id: 'tampered-challenge',
    expected: false,
    run: () => invoke(write('tampered-challenge', challengeTamper), '2030-01-01T00:05:00Z')
  },
  {
    id: 'expired-challenge',
    expected: false,
    run: () => invoke(vectorPath, '2030-01-01T00:11:00Z')
  }
];

const results = cases.map(test => {
  const observed = test.run();
  const passed = observed.valid === test.expected && (test.expected ? observed.exit_code === 0 : observed.exit_code !== 0);
  return { id: test.id, expected_valid: test.expected, passed, observed };
});

const passed = results.every(r => r.passed);
console.log(JSON.stringify({
  schema: challenge.result_contract?.schema || 'aml-verifier-conformance-result/1',
  prototype: true,
  challenge_schema: challenge.schema,
  challenge_sha256: challengeSha256,
  witness_vector_sha256: witnessVectorSha256,
  harness_root: repoRoot,
  command: [command, ...baseArgs],
  passed,
  results,
  claim_boundary: 'PASS is project-defined black-box compatibility evidence bound to the exact published challenge and witness-vector bytes; it is not certification or proof of verifier independence.'
}, null, 2));

process.exit(passed ? 0 : 1);
