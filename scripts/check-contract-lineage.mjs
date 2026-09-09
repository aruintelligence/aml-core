import fs from 'node:fs';

const catalog = JSON.parse(fs.readFileSync('protocol/verification-contract-catalog.json', 'utf8'));
const lineage = JSON.parse(fs.readFileSync('protocol/verification-contract-lineage.json', 'utf8'));

const failures = [];
const snapshots = catalog.snapshots || [];
const migrations = catalog.migrations || [];
const nodes = lineage.nodes || [];
const edges = lineage.edges || [];
const CLASSES = new Set(['backward-compatible', 'conditionally-compatible', 'breaking']);

const snapshotIds = snapshots.map((s) => s.snapshot_id);
if (new Set(snapshotIds).size !== snapshotIds.length) failures.push('duplicate snapshot id');
if (!snapshotIds.includes(catalog.current_snapshot)) failures.push('current_snapshot missing from catalog');

for (const snapshot of snapshots) {
  if (!fs.existsSync(snapshot.manifest)) failures.push(`missing snapshot manifest: ${snapshot.manifest}`);
  if (!/^[0-9a-f]{40}$/.test(snapshot.source_commit || '')) failures.push(`invalid source commit: ${snapshot.snapshot_id}`);
  if (fs.existsSync(snapshot.manifest)) {
    const manifest = JSON.parse(fs.readFileSync(snapshot.manifest, 'utf8'));
    if (manifest.snapshot_id !== snapshot.snapshot_id) failures.push(`${snapshot.snapshot_id}: catalog/manifest id mismatch`);
    if (manifest.source_commit !== snapshot.source_commit) failures.push(`${snapshot.snapshot_id}: catalog/manifest source commit mismatch`);
  }
}

const nodeIds = nodes.map((n) => n.snapshot_id);
if (new Set(nodeIds).size !== nodeIds.length) failures.push('duplicate lineage node');
for (const id of snapshotIds) if (!nodeIds.includes(id)) failures.push(`catalog snapshot missing from lineage: ${id}`);
for (const id of nodeIds) if (!snapshotIds.includes(id)) failures.push(`lineage node missing from catalog: ${id}`);
for (const node of nodes) {
  const catalogEntry = snapshots.find((item) => item.snapshot_id === node.snapshot_id);
  if (catalogEntry && node.source_commit !== catalogEntry.source_commit) failures.push(`${node.snapshot_id}: lineage/catalog source commit mismatch`);
}

const seenMigrationPaths = new Set();
for (const edge of edges) {
  if (!snapshotIds.includes(edge.from_snapshot)) failures.push(`edge source missing: ${edge.from_snapshot}`);
  if (!snapshotIds.includes(edge.to_snapshot)) failures.push(`edge target missing: ${edge.to_snapshot}`);
  if (!migrations.includes(edge.migration)) failures.push(`edge migration missing from catalog: ${edge.migration}`);
  if (!fs.existsSync(edge.migration)) {
    failures.push(`migration file missing: ${edge.migration}`);
    continue;
  }
  if (seenMigrationPaths.has(edge.migration)) failures.push(`migration file reused by multiple edges: ${edge.migration}`);
  seenMigrationPaths.add(edge.migration);

  const migration = JSON.parse(fs.readFileSync(edge.migration, 'utf8'));
  if (migration.schema !== 'aml-verification-contract-migration/1') failures.push(`${edge.migration}: wrong migration schema`);
  if (migration.from_snapshot !== edge.from_snapshot) failures.push(`${edge.migration}: from_snapshot does not match lineage edge`);
  if (migration.to_snapshot !== edge.to_snapshot) failures.push(`${edge.migration}: to_snapshot does not match lineage edge`);
  if (!CLASSES.has(migration.classification)) failures.push(`${edge.migration}: invalid compatibility classification`);
  if (!Array.isArray(migration.changed_locked_paths)) failures.push(`${edge.migration}: changed_locked_paths must be an array`);
  if (migration?.historical_artifacts?.old_snapshot_verification_required !== true) failures.push(`${edge.migration}: old snapshot verification must remain required`);
  if (migration?.historical_artifacts?.new_snapshot_may_reinterpret_old_artifacts !== false) failures.push(`${edge.migration}: old artifacts may not be reinterpreted`);
}
for (const migration of migrations) {
  if (!edges.some((edge) => edge.migration === migration)) failures.push(`catalog migration is not used by lineage: ${migration}`);
}

for (let i = 1; i < snapshots.length; i += 1) {
  const target = snapshots[i].snapshot_id;
  const incoming = edges.filter((edge) => edge.to_snapshot === target);
  if (incoming.length !== 1) failures.push(`${target} must have exactly one predecessor edge`);
}

const adjacency = new Map(snapshotIds.map((id) => [id, []]));
for (const edge of edges) adjacency.get(edge.from_snapshot)?.push(edge.to_snapshot);
const visiting = new Set();
const visited = new Set();
function visit(id) {
  if (visiting.has(id)) return false;
  if (visited.has(id)) return true;
  visiting.add(id);
  for (const next of adjacency.get(id) || []) if (!visit(next)) return false;
  visiting.delete(id);
  visited.add(id);
  return true;
}
for (const id of snapshotIds) if (!visit(id)) failures.push('migration lineage contains cycle');

if (snapshots.length === 1 && (migrations.length !== 0 || edges.length !== 0)) {
  failures.push('single-snapshot lineage must not invent migration edges');
}

if (failures.length) {
  console.error(JSON.stringify({ verified: false, failures }, null, 2));
  process.exit(1);
}

console.log(JSON.stringify({
  verified: true,
  snapshot_count: snapshots.length,
  migration_count: migrations.length,
  current_snapshot: catalog.current_snapshot,
  promise: 'Verifier contract evolution is explicit, acyclic, content-checked, and historically anchored.'
}, null, 2));
