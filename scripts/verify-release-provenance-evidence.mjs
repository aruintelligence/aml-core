import fs from 'node:fs';
import crypto from 'node:crypto';
import { spawnSync } from 'node:child_process';

function sha256(data) { return crypto.createHash('sha256').update(data).digest('hex'); }
function readJson(file) { return JSON.parse(fs.readFileSync(file, 'utf8')); }
function git(...args) {
  const run = spawnSync('git', args, { encoding: 'utf8' });
  if (run.status !== 0) throw new Error(run.stderr || `git ${args.join(' ')} failed`);
  return run.stdout.trim();
}
function fail(message) { console.error(message); process.exit(1); }

const evidencePath = process.argv[2];
if (!evidencePath) fail('Usage: node scripts/verify-release-provenance-evidence.mjs <evidence.json>');
const evidence = readJson(evidencePath);
if (evidence.protocol !== 'aml-release-provenance-evidence/1') fail('Unsupported provenance protocol');
const pkg = readJson('package.json');
const rollback = readJson('rollback-contract.json');
const channels = readJson('release-channels.json');
if (evidence.package !== pkg.name || evidence.version !== pkg.version) fail('Package identity mismatch');
if (evidence.control_commit !== git('rev-parse', 'HEAD')) fail('Control-plane commit mismatch');
const rollbackCommit = git('rev-parse', `${rollback.rollback_target.git_tag}^{commit}`);
if (evidence.rollback_target?.commit !== rollbackCommit) fail('Rollback commit mismatch');
if (evidence.rollback_target?.version !== rollback.rollback_target.version || evidence.rollback_target?.git_tag !== rollback.rollback_target.git_tag) fail('Rollback target identity mismatch');

for (const [file, expected] of Object.entries(evidence.contract_sha256 || {})) {
  if (!fs.existsSync(file)) fail(`Missing bound contract: ${file}`);
  const observed = sha256(fs.readFileSync(file));
  if (observed !== expected) fail(`Contract hash mismatch: ${file}`);
}

const bindingMaterial = JSON.stringify({
  package: evidence.package,
  version: evidence.version,
  control_commit: evidence.control_commit,
  rollback_target: evidence.rollback_target,
  channels,
  contracts: evidence.contract_sha256
});
const root = sha256(bindingMaterial);
if (root !== evidence.evidence_root_sha256) fail('Evidence root mismatch');

console.log(JSON.stringify({
  valid: true,
  protocol: 'aml-release-provenance-verification/1',
  evidence_root_sha256: root,
  control_commit: evidence.control_commit,
  rollback_commit: rollbackCommit,
  verified_contract_count: Object.keys(evidence.contract_sha256 || {}).length,
  claim_boundary: 'Project-controlled verification from this checkout; not third-party attestation or registry publication proof.'
}, null, 2));
