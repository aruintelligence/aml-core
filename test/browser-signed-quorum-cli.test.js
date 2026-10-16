import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { webcrypto } from 'node:crypto';

if (!globalThis.crypto?.subtle) globalThis.crypto = webcrypto;

import { createVerifierKeyPair, signVerificationReport } from '../docs/aml-signed-verification-report.js';
import { createSignedVerificationQuorum } from '../docs/aml-signed-verification-quorum.js';

function report(verifier) {
  return {
    schema: 'aml-verification-report/1', prototype: true, verifier,
    artifact_type: 'aml-witness-bundle/1', artifact_hash: 'a'.repeat(64),
    valid: true, reason: 'AML_WITNESS_BUNDLE_VALID',
    checked_at: '2030-01-01T00:05:00.000Z', checks: {}, notes: []
  };
}

test('offline CLI verifies a saved signed quorum and gates on its threshold', async (t) => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'aml-signed-quorum-cli-'));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const write = (name, value) => {
    const file = path.join(directory, name);
    fs.writeFileSync(file, `${JSON.stringify(value)}\n`);
    return file;
  };
  const run = (...args) => spawnSync(process.execPath, ['bin/aml.js', 'verify-signed-quorum', ...args], {
    cwd: process.cwd(), encoding: 'utf8'
  });

  const a = await signVerificationReport(report('a'), await createVerifierKeyPair());
  const b = await signVerificationReport(report('b'), await createVerifierKeyPair());
  const quorum = await createSignedVerificationQuorum([a, b], { threshold: 2 });
  const valid = run(write('quorum.json', quorum));
  assert.equal(valid.status, 0, valid.stderr);
  assert.equal(JSON.parse(valid.stdout).threshold_met, true);

  const inflated = structuredClone(quorum);
  inflated.summary.distinct_keys = 3;
  const rejected = run(write('inflated.json', inflated));
  assert.equal(rejected.status, 2, rejected.stderr);
  assert.equal(JSON.parse(rejected.stdout).reason, 'AML_SIGNED_QUORUM_MISMATCH');

  const unmet = await createSignedVerificationQuorum([a], { threshold: 2 });
  const belowThreshold = run(write('unmet.json', unmet));
  assert.equal(belowThreshold.status, 2, belowThreshold.stderr);
  assert.equal(JSON.parse(belowThreshold.stdout).valid, true);
  assert.equal(JSON.parse(belowThreshold.stdout).threshold_met, false);

  const missing = run();
  assert.equal(missing.status, 1);
  assert.match(missing.stderr, /Usage: aml verify-signed-quorum/);
});
