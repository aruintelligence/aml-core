import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';

function writeIntent(name, properties) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'aml-cli-'));
  const file = path.join(dir, `${name}.json`);
  fs.writeFileSync(file, JSON.stringify({
    transmission: name,
    nodes: [{ type: 'message', identifier: name, properties }]
  }), 'utf8');
  return file;
}

function run(args) {
  return spawnSync(process.execPath, ['bin/aml.js', ...args], {
    cwd: process.cwd(),
    encoding: 'utf8'
  });
}

const pressure = () => writeIntent('pressure_cli', {
  purpose: 'Create urgency',
  content: 'Act now',
  attention_cost: 5,
  restoration_value: 1
});

test('aml deploy shadow reports suppression without failing effective rollout', () => {
  const file = pressure();
  const result = run([
    'deploy', file,
    '--mode', 'shadow',
    '--profile', 'calm_default',
    '--timestamp', '2030-01-01T00:00:00.000Z'
  ]);
  assert.equal(result.status, 0, result.stderr);
  const body = JSON.parse(result.stdout);
  assert.equal(body.aml_allowed, false);
  assert.equal(body.effective_allowed, true);
  assert.equal(body.would_suppress, true);
});

test('aml deploy can become a blocking CI gate with explicit flag', () => {
  const file = pressure();
  const result = run([
    'deploy', file,
    '--mode', 'enforce',
    '--profile', 'calm_default',
    '--timestamp', '2030-01-01T00:00:00.000Z',
    '--require-effective-allow'
  ]);
  assert.equal(result.status, 3);
  const body = JSON.parse(result.stdout);
  assert.equal(body.effective_allowed, false);
});

test('aml canary can fail CI only when requested and a decision changes', () => {
  const file = writeIntent('privacy_cli', {
    purpose: 'Collect optional personal data',
    attention_cost: 1,
    restoration_value: 4,
    collects_personal_data: true
  });
  const result = run([
    'canary', file,
    '--baseline', 'calm_default',
    '--candidate', 'privacy_first',
    '--timestamp', '2030-01-01T00:00:00.000Z',
    '--fail-on-change'
  ]);
  assert.equal(result.status, 4, result.stderr);
  const body = JSON.parse(result.stdout);
  assert.equal(body.changed_decisions >= 1, true);
  assert.equal(body.candidate_new_suppressions >= 1, true);
});
