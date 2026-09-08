#!/usr/bin/env node
import fs from 'node:fs';

const snapshotPath = process.argv[2] || 'protocol/verification-contract-v1.json';
const snapshot = JSON.parse(fs.readFileSync(snapshotPath, 'utf8'));
const failures = [];

if (snapshot.schema !== 'aml-verification-contract-snapshot/1') failures.push('unexpected schema');
if (!/^[0-9a-f]{40}$/.test(snapshot.source_commit || '')) failures.push('source_commit must be a full Git SHA');
if (snapshot.canonicalization !== 'sorted-json-v1') failures.push('unexpected canonicalization profile');
if (snapshot.witness_schema !== 'aml-witness-bundle/1') failures.push('unexpected witness schema');
if (!Array.isArray(snapshot.locked_paths) || snapshot.locked_paths.length === 0) failures.push('locked_paths missing');
if (!Array.isArray(snapshot.required_behavior) || snapshot.required_behavior.length < 4) failures.push('required_behavior incomplete');

const seen = new Set();
for (const path of snapshot.locked_paths || []) {
  if (seen.has(path)) failures.push(`duplicate locked path: ${path}`);
  seen.add(path);
  if (!fs.existsSync(path)) failures.push(`locked path missing from current tree: ${path}`);
}

for (const path of [snapshot.cli_contract, snapshot.golden_vector]) {
  if (!path || !fs.existsSync(path)) failures.push(`required snapshot path missing: ${path}`);
}

if (failures.length) {
  console.error(JSON.stringify({ verified: false, snapshot_id: snapshot.snapshot_id || null, failures }, null, 2));
  process.exit(1);
}

console.log(JSON.stringify({
  verified: true,
  schema: snapshot.schema,
  snapshot_id: snapshot.snapshot_id,
  source_commit: snapshot.source_commit,
  locked_path_count: snapshot.locked_paths.length,
  canonicalization: snapshot.canonicalization,
  witness_schema: snapshot.witness_schema,
  claim_boundary: 'This guard verifies snapshot structure and current-path presence. The immutable source_commit is the historical contract anchor.'
}, null, 2));
