import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';

const read = (path) => JSON.parse(fs.readFileSync(path, 'utf8'));

test('verification contract catalog starts with one real snapshot and no fake migration', () => {
  const catalog = read('protocol/verification-contract-catalog.json');
  assert.equal(catalog.schema, 'aml-verification-contract-catalog/1');
  assert.equal(catalog.snapshots.length, 1);
  assert.equal(catalog.migrations.length, 0);
  assert.equal(catalog.current_snapshot, 'aml-verifier-contract-2026-09-08-01');
});

test('verification contract lineage is acyclic bootstrap state', () => {
  const lineage = read('protocol/verification-contract-lineage.json');
  assert.equal(lineage.schema, 'aml-verification-contract-lineage/1');
  assert.equal(lineage.nodes.length, 1);
  assert.equal(lineage.edges.length, 0);
});

test('migration schema preserves historical snapshot meaning', () => {
  const schema = read('protocol/aml-verification-contract-migration.schema.json');
  const historical = schema.properties.historical_artifacts.properties;
  assert.equal(historical.old_snapshot_verification_required.const, true);
  assert.equal(historical.new_snapshot_may_reinterpret_old_artifacts.const, false);
});

test('migration classifications remain explicit and finite', () => {
  const schema = read('protocol/aml-verification-contract-migration.schema.json');
  assert.deepEqual(schema.properties.classification.enum, [
    'backward-compatible',
    'conditionally-compatible',
    'breaking'
  ]);
});
