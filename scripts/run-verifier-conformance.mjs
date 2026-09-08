#!/usr/bin/env node
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';

const split = process.argv.indexOf('--');
if (split < 0 || split === process.argv.length - 1) {
  console.error('usage: node scripts/run-verifier-conformance.mjs -- <verifier-command> [args...]');
  process.exit(2);
}

const command = process.argv[split + 1];
const baseArgs = process.argv.slice(split + 2);
const vectorPath = path.resolve('independent/python/witness-vector.json');
const source = JSON.parse(fs.readFileSync(vectorPath, 'utf8'));
const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'aml-verifier-conformance-'));

function invoke(bundlePath, now) {
  const result = spawnSync(command, [...baseArgs, '--now', now, bundlePath], {
    encoding: 'utf8'
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
  schema: 'aml-verifier-conformance-result/1',
  prototype: true,
  command: [command, ...baseArgs],
  passed,
  results,
  claim_boundary: 'PASS is project-defined black-box compatibility evidence, not certification or proof of verifier independence.'
}, null, 2));

process.exit(passed ? 0 : 1);
