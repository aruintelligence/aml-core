import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';

const read = (path) => JSON.parse(fs.readFileSync(path, 'utf8'));
const SNAPSHOT_1 = 'aml-verifier-contract-2026-09-08-01';
const SNAPSHOT_2 = 'aml-verifier-contract-2026-09-09-01';
const MIGRATION = 'protocol/migrations/aml-verifier-contract-2026-09-08-01_to_2026-09-09-01.json';

test('verification contract catalog preserves Snapshot 1 and advances explicitly to Snapshot 2', () => {
  const catalog = read('protocol/verification-contract-catalog.json');
  assert.equal(catalog.schema, 'aml-verification-contract-catalog/1');
  assert.equal(catalog.snapshots.length, 2);
  assert.equal(catalog.migrations.length, 1);
  assert.equal(catalog.current_snapshot, SNAPSHOT_2);

  const first = catalog.snapshots.find((entry) => entry.snapshot_id === SNAPSHOT_1);
  const second = catalog.snapshots.find((entry) => entry.snapshot_id === SNAPSHOT_2);
  assert.ok(first);
  assert.ok(second);
  assert.equal(first.manifest, 'protocol/verification-contract-v1.json');
  assert.equal(first.superseded, true);
  assert.equal(second.manifest, 'protocol/verification-contract-v2.json');
  assert.equal(second.superseded, false);
  assert.deepEqual(catalog.migrations, [MIGRATION]);
});

test('verification contract lineage has one acyclic predecessor edge into Snapshot 2', () => {
  const lineage = read('protocol/verification-contract-lineage.json');
  assert.equal(lineage.schema, 'aml-verification-contract-lineage/1');
  assert.equal(lineage.nodes.length, 2);
  assert.equal(lineage.edges.length, 1);
  assert.deepEqual(
    lineage.nodes.map((node) => node.snapshot_id),
    [SNAPSHOT_1, SNAPSHOT_2]
  );
  assert.deepEqual(lineage.edges[0], {
    from_snapshot: SNAPSHOT_1,
    to_snapshot: SNAPSHOT_2,
    migration: MIGRATION
  });
  assert.notEqual(lineage.edges[0].from_snapshot, lineage.edges[0].to_snapshot);
});

test('Snapshot 2 migration is explicit, breaking, and preserves Snapshot 1 historical meaning', () => {
  const migration = read(MIGRATION);
  assert.equal(migration.schema, 'aml-verification-contract-migration/1');
  assert.equal(migration.from_snapshot, SNAPSHOT_1);
  assert.equal(migration.to_snapshot, SNAPSHOT_2);
  assert.equal(migration.classification, 'breaking');
  assert.deepEqual(migration.changed_locked_paths, [
    'protocol/aml-verifier-conformance-result.schema.json',
    'scripts/run-verifier-conformance.mjs'
  ]);
  assert.equal(migration.historical_artifacts.old_snapshot_verification_required, true);
  assert.equal(migration.historical_artifacts.new_snapshot_may_reinterpret_old_artifacts, false);
  assert.ok(migration.behavior_changes.some((change) => change.compatibility === 'incompatible'));
  assert.ok(migration.behavior_changes.some((change) => change.compatibility === 'compatible'));
});

test('Snapshot 1 remains an immutable historical target while Snapshot 2 adds evidence bindings', () => {
  const first = read('protocol/verification-contract-v1.json');
  const second = read('protocol/verification-contract-v2.json');
  assert.equal(first.snapshot_id, SNAPSHOT_1);
  assert.equal(second.snapshot_id, SNAPSHOT_2);
  assert.notEqual(first.source_commit, second.source_commit);
  assert.ok(!first.locked_paths.includes('conformance/verifier-challenge.json'));
  assert.ok(second.locked_paths.includes('conformance/verifier-challenge.json'));
  assert.ok(second.locked_paths.includes('scripts/verify-verifier-conformance-result.mjs'));
  assert.ok(second.required_behavior.some((behavior) => behavior.includes('exact external verifier challenge bytes')));
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
