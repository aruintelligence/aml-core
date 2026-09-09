import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';

const challengeBytes = fs.readFileSync('conformance/verifier-challenge.json');
const vectorBytes = fs.readFileSync('independent/python/witness-vector.json');
const challenge = JSON.parse(challengeBytes.toString('utf8'));
const sha256 = (bytes) => crypto.createHash('sha256').update(bytes).digest('hex');

function goodResult() {
  const results = challenge.cases.map((entry) => ({
    id: entry.id,
    expected_valid: entry.expected_valid,
    passed: true,
    observed: {
      exit_code: entry.expected_valid ? 0 : 1,
      valid: entry.expected_valid,
      reason: null,
      stdout: JSON.stringify({ valid: entry.expected_valid }),
      stderr: ''
    }
  }));
  return {
    schema: challenge.result_contract.schema,
    prototype: true,
    challenge_schema: challenge.schema,
    challenge_sha256: sha256(challengeBytes),
    witness_vector_sha256: sha256(vectorBytes),
    harness_root: '/outside/checkout',
    command: ['./verify'],
    passed: true,
    results,
    claim_boundary: 'test fixture'
  };
}

function verify(result) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'aml-result-proof-'));
  const file = path.join(dir, 'result.json');
  fs.writeFileSync(file, JSON.stringify(result));
  const run = spawnSync(process.execPath, ['scripts/verify-verifier-conformance-result.mjs', file], { encoding: 'utf8' });
  fs.rmSync(dir, { recursive: true, force: true });
  return { status: run.status, stdout: run.stdout, stderr: run.stderr };
}

test('challenge contract requires exact challenge and vector bindings', () => {
  assert.equal(challenge.result_contract.schema, 'aml-verifier-conformance-result/1');
  assert.equal(challenge.result_contract.must_bind_exact_challenge_sha256, true);
  assert.equal(challenge.result_contract.must_bind_exact_witness_vector_sha256, true);
  assert.equal(challenge.result_contract.verifier, 'scripts/verify-verifier-conformance-result.mjs');
});

test('archived conformance result verifies against exact local challenge bytes', () => {
  const run = verify(goodResult());
  assert.equal(run.status, 0, run.stderr || run.stdout);
  assert.equal(JSON.parse(run.stdout).verified, true);
});

test('archived result rejects rewritten challenge and witness-vector hashes', () => {
  for (const field of ['challenge_sha256', 'witness_vector_sha256']) {
    const result = goodResult();
    result[field] = '0'.repeat(64);
    const run = verify(result);
    assert.equal(run.status, 1, `${field} tamper must fail`);
    assert.equal(JSON.parse(run.stdout).verified, false);
  }
});

test('archived result rejects case reorder, expected-verdict rewrite, and PASS rewrite', () => {
  const reorder = goodResult();
  [reorder.results[0], reorder.results[1]] = [reorder.results[1], reorder.results[0]];
  assert.equal(verify(reorder).status, 1);

  const verdict = goodResult();
  verdict.results[0].expected_valid = false;
  assert.equal(verify(verdict).status, 1);

  const top = goodResult();
  top.passed = false;
  assert.equal(verify(top).status, 1);
});

test('external verifier Action exports immutable challenge evidence identifiers', () => {
  const action = fs.readFileSync('actions/verifier-conformance/action.yml', 'utf8');
  assert.match(action, /challenge-sha256:/);
  assert.match(action, /witness-vector-sha256:/);
  assert.match(action, /challenge_sha256/);
  assert.match(action, /witness_vector_sha256/);
});
