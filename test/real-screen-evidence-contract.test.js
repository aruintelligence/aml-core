import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';

const schema = JSON.parse(fs.readFileSync('schema/real-screen-evidence-manifest.schema.json', 'utf8'));
const readme = fs.readFileSync('evidence/real-screen/README.md', 'utf8');

test('real-screen evidence manifest requires provenance, hashes, reproducibility and explicit eligibility', () => {
  assert.equal(schema.properties.schema.const, 'aml-real-screen-evidence-manifest/1');
  for (const field of ['source', 'capture', 'labels', 'aml', 'receipt', 'reproducibility', 'real_screen_evidence_eligible', 'claim_boundary']) {
    assert.ok(schema.required.includes(field), `manifest must require ${field}`);
  }
  assert.equal(schema.properties.real_screen_evidence_eligible.type, 'boolean');
  assert.equal(schema.properties.capture.properties.artifacts.items.properties.sha256.pattern, '^[a-f0-9]{64}$');
  assert.equal(schema.properties.labels.properties.sha256.pattern, '^[a-f0-9]{64}$');
  assert.equal(schema.properties.receipt.properties.sha256.pattern, '^[a-f0-9]{64}$');
});

test('real-screen corpus documentation refuses invented historical evidence and objective cognition claims', () => {
  assert.match(readme, /Do not manufacture missing timestamps, screenshots, hashes, browser metadata, or post-deployment observations/);
  assert.match(readme, /not objective measurements of cognition/i);
  assert.match(readme, /not independent validation/i);
  assert.match(readme, /legacy\/unmigrated/i);
});
