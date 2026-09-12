import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';

function run(target) {
  const result = spawnSync(process.execPath, ['scripts/package-content-manifest.mjs', target], { encoding: 'utf8' });
  if (result.status !== 0) {
    console.error(result.stderr || result.stdout);
    process.exit(result.status || 1);
  }
  return JSON.parse(fs.readFileSync(target, 'utf8'));
}

const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'aml-package-repro-'));
const firstPath = path.join(dir, 'first.json');
const secondPath = path.join(dir, 'second.json');
const first = run(firstPath);
const second = run(secondPath);
if (first.content_root_sha256 !== second.content_root_sha256) {
  console.error(`Package content root is not reproducible: ${first.content_root_sha256} != ${second.content_root_sha256}`);
  process.exit(1);
}
if (JSON.stringify(first.files) !== JSON.stringify(second.files)) {
  console.error('Package file manifest changed between consecutive dry runs');
  process.exit(1);
}
process.stdout.write(`${JSON.stringify({
  protocol: 'aml-package-reproducibility-verification/1',
  valid: true,
  package: first.package,
  version: first.version,
  file_count: first.file_count,
  content_root_sha256: first.content_root_sha256,
  repeated_runs: 2,
  claim_boundary: 'Project-controlled reproducibility check for npm-selected file content in one checkout; not registry publication or third-party reproducibility evidence.'
}, null, 2)}\n`);
