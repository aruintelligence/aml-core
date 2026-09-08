#!/usr/bin/env node
import fs from 'node:fs';
import { execFileSync } from 'node:child_process';

const snapshotPath = process.argv[2] || 'protocol/verification-contract-v1.json';
const snapshot = JSON.parse(fs.readFileSync(snapshotPath, 'utf8'));
const changed = [];
const missingAtAnchor = [];

for (const path of snapshot.locked_paths || []) {
  let anchored;
  try {
    anchored = execFileSync('git', ['show', `${snapshot.source_commit}:${path}`], { encoding: null });
  } catch {
    missingAtAnchor.push(path);
    continue;
  }
  const current = fs.readFileSync(path);
  if (!anchored.equals(current)) changed.push(path);
}

if (missingAtAnchor.length || changed.length) {
  console.error(JSON.stringify({
    verified: false,
    snapshot_id: snapshot.snapshot_id,
    source_commit: snapshot.source_commit,
    changed_locked_paths: changed,
    missing_at_anchor: missingAtAnchor,
    required_action: 'Publish a new verifier contract snapshot instead of silently changing the meaning of an existing snapshot.'
  }, null, 2));
  process.exit(1);
}

console.log(JSON.stringify({
  verified: true,
  snapshot_id: snapshot.snapshot_id,
  source_commit: snapshot.source_commit,
  locked_path_count: snapshot.locked_paths.length,
  drifted_path_count: 0,
  promise: 'Every locked verifier contract path is byte-identical to the immutable source commit.'
}, null, 2));
