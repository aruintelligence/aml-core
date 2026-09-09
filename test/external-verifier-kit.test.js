import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { buildExternalVerifierKit } from '../scripts/build-external-verifier-kit.mjs';
import { checkExternalVerifierKit } from '../scripts/check-external-verifier-kit.mjs';

const sha256 = (bytes) => crypto.createHash('sha256').update(bytes).digest('hex');

test('external verifier kit is reference-code-free, Snapshot 2 aware, and self-consistent', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'aml-verifier-kit-'));
  try {
    const output = path.join(root, 'kit');
    const built = buildExternalVerifierKit(output);
    const checked = checkExternalVerifierKit(output);
    assert.equal(checked.valid, true, JSON.stringify(checked.failures));
    assert.equal(built.manifest.reference_code_included, false);
    assert.equal(built.manifest.current_contract_snapshot_id, 'aml-verifier-contract-2026-09-09-01');
    assert.equal(built.manifest.contract_snapshot_count, 2);
    assert.equal(built.manifest.contract_migration_count, 1);
    assert.equal(built.manifest.challenge_sha256, sha256(fs.readFileSync('conformance/verifier-challenge.json')));
    assert.equal(built.manifest.witness_vector_sha256, sha256(fs.readFileSync('independent/python/witness-vector.json')));
    for (const required of [
      'conformance/verifier-challenge.json',
      'independent/python/witness-vector.json',
      'protocol/sorted-json-v1.md',
      'protocol/verification-contract-v1.json',
      'protocol/verification-contract-v2.json',
      'protocol/verification-contract-catalog.json',
      'protocol/verification-contract-lineage.json',
      'protocol/migrations/aml-verifier-contract-2026-09-08-01_to_2026-09-09-01.json'
    ]) {
      assert.ok(built.manifest.files.some((entry) => entry.path === required), required);
    }
    for (const entry of built.manifest.files) {
      assert.doesNotMatch(entry.path, /\.(?:js|mjs|cjs|ts|tsx|jsx|py|go|rs|java|kt|cs|c|cc|cpp|h|hpp|swift|zig|rb|php|sh|bash|ps1)$/i);
    }
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('external verifier kit detects post-build vector tampering', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'aml-verifier-kit-tamper-'));
  try {
    const output = path.join(root, 'kit');
    buildExternalVerifierKit(output);
    const target = path.join(output, 'independent/python/witness-vector.json');
    fs.appendFileSync(target, '\n');
    const checked = checkExternalVerifierKit(output);
    assert.equal(checked.valid, false);
    assert.ok(checked.failures.some((failure) => failure.includes('SHA-256 mismatch')));
    assert.ok(checked.failures.some((failure) => failure.includes('witness_vector_sha256 mismatch')));
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('external verifier kit detects contract catalog substitution even with unchanged manifest entry metadata', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'aml-verifier-kit-contract-'));
  try {
    const output = path.join(root, 'kit');
    buildExternalVerifierKit(output);
    const catalogPath = path.join(output, 'protocol/verification-contract-catalog.json');
    const catalog = JSON.parse(fs.readFileSync(catalogPath, 'utf8'));
    catalog.current_snapshot = 'aml-verifier-contract-2026-09-08-01';
    fs.writeFileSync(catalogPath, JSON.stringify(catalog, null, 2));
    const checked = checkExternalVerifierKit(output);
    assert.equal(checked.valid, false);
    assert.ok(checked.failures.some((failure) => failure.includes('SHA-256 mismatch') || failure.includes('current contract snapshot')));
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('external verifier kit manifest root is deterministic for identical source material', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'aml-verifier-kit-root-'));
  try {
    const one = buildExternalVerifierKit(path.join(root, 'one')).manifest;
    const two = buildExternalVerifierKit(path.join(root, 'two')).manifest;
    assert.match(one.root_sha256, /^[a-f0-9]{64}$/);
    assert.equal(one.root_sha256, two.root_sha256);
    assert.equal(one.challenge_sha256, two.challenge_sha256);
    assert.equal(one.witness_vector_sha256, two.witness_vector_sha256);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});
