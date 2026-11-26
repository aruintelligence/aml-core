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

test('aml deploy shadow reports suppression but a policy denial never exits 0 (Directive 009)', () => {
  const file = pressure();
  const base = ['deploy', file, '--mode', 'shadow', '--profile', 'calm_default', '--timestamp', '2030-01-01T00:00:00.000Z'];
  const denied = run(base);
  assert.equal(denied.status, 3, 'shadow effective_allowed is observability, not authorization');
  const deniedBody = JSON.parse(denied.stdout);
  assert.equal(deniedBody.effective_allowed, true);
  assert.equal(deniedBody.authorization.authorized, false);
  assert.deepEqual(deniedBody.authorization.reasons, ['AML_AUTHZ_POLICY_DENIED']);
  const result = run([...base, '--diagnostic-only']);
  assert.equal(result.status, 0, result.stderr);
  const body = JSON.parse(result.stdout);
  assert.equal(body.authorization.authorized, false);
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

test('aml deploy positive control: a policy-allowed intent exits 0 with authorized true', () => {
  const file = writeIntent('benign_cli', { purpose: 'Inform', content: 'Your order shipped', attention_cost: 1, restoration_value: 5 });
  for (const mode of ['shadow', 'enforce']) {
    const result = run(['deploy', file, '--mode', mode, '--profile', 'calm_default', '--timestamp', '2030-01-01T00:00:00.000Z']);
    assert.equal(result.status, 0, result.stderr);
    const body = JSON.parse(result.stdout);
    assert.equal(body.aml_allowed, true);
    assert.equal(body.authorization.authorized, true);
  }
});
