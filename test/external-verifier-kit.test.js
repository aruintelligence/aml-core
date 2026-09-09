import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { buildExternalVerifierKit } from '../scripts/build-external-verifier-kit.mjs';
import { checkExternalVerifierKit } from '../scripts/check-external-verifier-kit.mjs';

test('external verifier kit is reference-code-free and self-consistent', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'aml-verifier-kit-'));
  try {
    const output = path.join(root, 'kit');
    const built = buildExternalVerifierKit(output);
    const checked = checkExternalVerifierKit(output);
    assert.equal(checked.valid, true, JSON.stringify(checked.failures));
    assert.equal(built.manifest.reference_code_included, false);
    assert.ok(built.manifest.files.some((entry) => entry.path === 'conformance/verifier-challenge.json'));
    assert.ok(built.manifest.files.some((entry) => entry.path === 'independent/python/witness-vector.json'));
    assert.ok(built.manifest.files.some((entry) => entry.path === 'protocol/sorted-json-v1.md'));
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
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('external verifier kit manifest root changes when included material changes', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'aml-verifier-kit-root-'));
  try {
    const one = buildExternalVerifierKit(path.join(root, 'one')).manifest.root_sha256;
    const original = fs.readFileSync('conformance/witness-record.example.json', 'utf8');
    const tempSource = path.join(root, 'witness-record.example.json');
    fs.writeFileSync(tempSource, original);
    assert.match(one, /^[a-f0-9]{64}$/);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});
