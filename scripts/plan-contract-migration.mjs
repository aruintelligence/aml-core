import fs from 'node:fs';
import { execFileSync } from 'node:child_process';

const args = process.argv.slice(2);
const get = (name) => {
  const i = args.indexOf(name);
  return i >= 0 ? args[i + 1] : null;
};

const fromPath = get('--from');
const toPath = get('--to');
if (!fromPath || !toPath) {
  console.error('usage: node scripts/plan-contract-migration.mjs --from <snapshot.json> --to <snapshot.json>');
  process.exit(2);
}

const from = JSON.parse(fs.readFileSync(fromPath, 'utf8'));
const to = JSON.parse(fs.readFileSync(toPath, 'utf8'));
const fromSet = new Set(from.locked_paths || []);
const toSet = new Set(to.locked_paths || []);
const candidatePaths = [...new Set([...fromSet, ...toSet])].sort();
const changed = [];
const added = [];
const removed = [];

for (const path of candidatePaths) {
  if (!fromSet.has(path)) {
    added.push(path);
    changed.push(path);
    continue;
  }
  if (!toSet.has(path)) {
    removed.push(path);
    changed.push(path);
    continue;
  }
  try {
    execFileSync('git', ['diff', '--quiet', from.source_commit, to.source_commit, '--', path], { stdio: 'ignore' });
  } catch {
    changed.push(path);
  }
}

console.log(JSON.stringify({
  schema: 'aml-verification-contract-migration-plan/1',
  from_snapshot: from.snapshot_id,
  to_snapshot: to.snapshot_id,
  from_commit: from.source_commit,
  to_commit: to.source_commit,
  changed_locked_paths: changed,
  added_locked_paths: added,
  removed_locked_paths: removed,
  classification: changed.length === 0 ? 'no-contract-change' : 'REQUIRES_HUMAN_CLASSIFICATION',
  note: 'File changes are mechanical evidence only. Compatibility classification must describe behavior, not line count.'
}, null, 2));
