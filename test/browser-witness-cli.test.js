import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';

import { sealBrowserReceipt, sha256Browser } from '../docs/aml-browser-integrity.js';
import { createBrowserEvidence } from '../docs/aml-browser-evidence.js';
import { createVerificationChallenge } from '../docs/aml-verification-challenge.js';
import { createSessionAttestation } from '../docs/aml-session-attestation.js';
import { createWitnessBundle, witnessBundlePayload } from '../docs/aml-witness-bundle.js';

test('the CLI verifies a real signed bundle only against a retained challenge', async (t) => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'aml-witness-cli-'));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const write = (name, value) => {
    const file = path.join(directory, name);
    fs.writeFileSync(file, `${JSON.stringify(value)}\n`);
    return file;
  };
  const run = (...args) => spawnSync(process.execPath, ['bin/aml.js', 'verify-witness', ...args], {
    cwd: process.cwd(), encoding: 'utf8'
  });

  const receipt = await sealBrowserReceipt({ schema: 'aml-dom-receipt/1', decisions: [] });
  const evidence = await createBrowserEvidence(receipt, { url: 'https://example.test/' });
  const challenge = createVerificationChallenge({ ttl_ms: 120000 });
  const attestation = await createSessionAttestation({ evidence, challenge });
  const bundle = await createWitnessBundle({ evidence, challenge, attestation });
  const bundlePath = write('bundle.json', bundle);
  const heldPath = write('held.json', structuredClone(challenge));

  const valid = run(bundlePath, heldPath);
  assert.equal(valid.status, 0, valid.stderr);
  assert.equal(JSON.parse(valid.stdout).reason, 'AML_WITNESS_BUNDLE_VALID');

  const changed = structuredClone(bundle);
  changed.challenge.issued_at = new Date(Date.parse(challenge.issued_at) - 1000).toISOString();
  changed.integrity.value = await sha256Browser(witnessBundlePayload(changed));
  const rejected = run(write('changed.json', changed), heldPath);
  assert.equal(rejected.status, 2, rejected.stderr);
  assert.equal(JSON.parse(rejected.stdout).reason, 'AML_WITNESS_BUNDLE_CHALLENGE_MISMATCH');

  const tampered = structuredClone(bundle);
  tampered.evidence.receipt.decisions.push({ id: 'unbound' });
  const badHash = run(write('tampered.json', tampered), heldPath);
  assert.equal(badHash.status, 2, badHash.stderr);
  assert.equal(JSON.parse(badHash.stdout).reason, 'AML_WITNESS_BUNDLE_HASH_MISMATCH');

  const noChallenge = run(bundlePath);
  assert.equal(noChallenge.status, 1);
  assert.match(noChallenge.stderr, /verifier-held-challenge\.json/);

  const malformed = path.join(directory, 'malformed.json');
  fs.writeFileSync(malformed, '{');
  const badInput = run(malformed, heldPath);
  assert.equal(badInput.status, 1);
  assert.match(badInput.stderr, /ĀML command failed/);
});
