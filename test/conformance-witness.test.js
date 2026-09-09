import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {
  classifyConformanceResult,
  createWitnessRecordFromConformance,
  generateWitnessRecordFile
} from '../scripts/create-witness-record-from-conformance.mjs';
import { validateWitnessRecord } from '../scripts/validate-witness-record.mjs';

function sha256File(file) {
  return crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex');
}

const challenge = JSON.parse(fs.readFileSync('conformance/verifier-challenge.json', 'utf8'));
const challengeSha = sha256File('conformance/verifier-challenge.json');
const vectorSha = sha256File(challenge.witness_vector);

function resultWith(passes) {
  const results = passes.map((passed, index) => ({
    id: `case-${index + 1}`,
    expected_valid: index === 0,
    passed,
    observed: { exit_code: passed ? 0 : 1, valid: passed, reason: passed ? null : 'mismatch' }
  }));
  return {
    schema: 'aml-verifier-conformance-result/1',
    prototype: true,
    challenge_schema: 'aml-external-verifier-challenge/1',
    challenge_sha256: challengeSha,
    witness_vector_sha256: vectorSha,
    command: ['./external-verifier'],
    passed: results.every((item) => item.passed),
    results,
    claim_boundary: 'Compatibility evidence only.'
  };
}

test('conformance result classification preserves PASS MIXED and FAIL', () => {
  assert.equal(classifyConformanceResult(resultWith([true, true, true, true])), 'PASS');
  assert.equal(classifyConformanceResult(resultWith([true, false, true, false])), 'MIXED');
  assert.equal(classifyConformanceResult(resultWith([false, false, false, false])), 'FAIL');
});

test('generated witness record binds exact challenge bytes and validates', () => {
  const record = createWitnessRecordFromConformance({
    result: resultWith([true, false, true, false]),
    witnessId: 'example-verifier-run-123',
    sourceUrl: 'https://github.com/example/aml-verifier/actions/runs/123',
    verifier: 'example-verifier 0.1.0',
    runtime: 'rust-1.90',
    observedAt: '2026-09-09T08:00:00.000Z'
  });
  assert.equal(record.result, 'MIXED');
  assert.equal(record.artifact_type, 'aml-external-verifier-challenge/1');
  assert.equal(record.artifact_hash, challengeSha);
  assert.ok(record.notes.includes(`witness_vector_sha256=${vectorSha}`));
  assert.equal(validateWitnessRecord(record).valid, true);
});

test('file generator rejects conformance results bound to different challenge bytes', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'aml-conformance-witness-'));
  try {
    const input = path.join(root, 'result.json');
    const output = path.join(root, 'witness.json');
    fs.writeFileSync(input, JSON.stringify({ ...resultWith([true, true, true, true]), challenge_sha256: '0'.repeat(64) }));
    assert.throws(() => generateWitnessRecordFile({
      resultFile: input,
      outputFile: output,
      witnessId: 'example-verifier-run-124',
      sourceUrl: 'https://github.com/example/aml-verifier/actions/runs/124',
      observedAt: '2026-09-09T08:00:00.000Z'
    }), /challenge hash does not match/);
    assert.equal(fs.existsSync(output), false);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('file generator rejects contradictory top-level PASS metadata', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'aml-conformance-witness-contradiction-'));
  try {
    const input = path.join(root, 'result.json');
    const output = path.join(root, 'witness.json');
    fs.writeFileSync(input, JSON.stringify({ ...resultWith([true, false, true, false]), passed: true }));
    assert.throws(() => generateWitnessRecordFile({
      resultFile: input,
      outputFile: output,
      witnessId: 'example-verifier-run-125',
      sourceUrl: 'https://github.com/example/aml-verifier/actions/runs/125',
      observedAt: '2026-09-09T08:00:00.000Z'
    }), /passed flag disagrees/);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});
