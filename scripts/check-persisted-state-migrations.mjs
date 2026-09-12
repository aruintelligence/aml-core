import fs from 'node:fs';

function read(file) { return JSON.parse(fs.readFileSync(file, 'utf8')); }
function fail(message) { console.error(message); process.exit(1); }
function major(protocol) {
  const match = String(protocol).match(/\/(\d+)$/);
  if (!match) fail(`Invalid protocol identifier: ${protocol}`);
  return Number(match[1]);
}

const contract = read('persisted-state-contract.json');
const vectors = read('persisted-state-migration-vectors.json');
if (vectors.protocol !== 'aml-persisted-state-migration-vectors/1') fail('Unexpected migration-vector protocol');
if (contract.compatibility_policy?.migration_required_for_major_change !== true) fail('Persisted-state contract must require migration for major change');
if (contract.compatibility_policy?.silent_destructive_rewrite !== false) fail('Silent destructive rewrite must remain forbidden');

const results = [];
for (const vector of vectors.vectors || []) {
  const source = read(vector.source_fixture);
  if (source.protocol !== vector.source_protocol) fail(`${vector.id}: source protocol mismatch`);
  const sourceMajor = major(vector.source_protocol);
  const targetMajor = major(vector.target_protocol);
  const majorChanged = sourceMajor !== targetMajor;
  if (majorChanged !== Boolean(vector.migration_required)) fail(`${vector.id}: migration requirement inconsistent with major change`);

  let observed;
  if (majorChanged) {
    const migrated = {
      ...JSON.parse(JSON.stringify(source)),
      protocol: vector.target_protocol,
      migration: {
        protocol: 'aml-persisted-state-migration-record/1',
        from: vector.source_protocol,
        to: vector.target_protocol,
        vector_id: vector.id
      }
    };
    for (const field of vector.preserve || []) {
      if (JSON.stringify(migrated[field]) !== JSON.stringify(source[field])) fail(`${vector.id}: migration failed to preserve ${field}`);
    }
    if (!migrated.migration) fail(`${vector.id}: explicit migration record missing`);
    observed = 'explicit_migration_required';
  } else {
    const roundtrip = JSON.parse(JSON.stringify(source));
    for (const field of vector.preserve || []) {
      if (JSON.stringify(roundtrip[field]) !== JSON.stringify(source[field])) fail(`${vector.id}: roundtrip failed to preserve ${field}`);
    }
    observed = 'roundtrip_without_migration';
  }
  if (observed !== vector.expected) fail(`${vector.id}: expected ${vector.expected}, observed ${observed}`);
  results.push({ id: vector.id, observed, major_changed: majorChanged, synthetic_target_major: Boolean(vector.synthetic_target_major) });
}

console.log(JSON.stringify({
  valid: true,
  protocol: 'aml-persisted-state-migration-verification/1',
  results,
  claim_boundary: 'Project-controlled migration regression verification only. Synthetic target majors do not announce shipped protocols or prove arbitrary downstream migration safety.'
}, null, 2));
