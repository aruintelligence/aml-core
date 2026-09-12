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

const rollback = readJson('rollback-contract.json');
const channels = readJson('release-channels.json');
const pkg = readJson('package.json');
const files = [
  'project-contract.json',
  'package.json',
  'release-channels.json',
  'rollback-contract.json',
  'upgrade-contract.json',
  'support-policy.json',
  'protocol-compatibility.json',
  'persisted-state-contract.json',
  'persisted-state-migration-vectors.json'
];
const contracts = Object.fromEntries(files.sort().map(file => [file, sha256(fs.readFileSync(file))]));
const controlCommit = git('rev-parse', 'HEAD');
const rollbackCommit = git('rev-parse', `${rollback.rollback_target.git_tag}^{commit}`);
const bindingMaterial = JSON.stringify({
  package: pkg.name,
  version: pkg.version,
  control_commit: controlCommit,
  rollback_target: { ...rollback.rollback_target, commit: rollbackCommit },
  channels,
  contracts
});
const report = {
  protocol: 'aml-release-provenance-evidence/1',
  package: pkg.name,
  version: pkg.version,
  control_commit: controlCommit,
  rollback_target: { ...rollback.rollback_target, commit: rollbackCommit },
  contract_sha256: contracts,
  evidence_root_sha256: sha256(bindingMaterial),
  claim_boundary: 'Project-generated release provenance binding over repository contracts and Git commits. It is not a third-party attestation, registry publication proof, signature, or independent supply-chain certification.'
};
const target = process.argv[2] || 'aml-release-provenance-evidence.json';
fs.writeFileSync(target, `${JSON.stringify(report, null, 2)}\n`);
console.log(JSON.stringify(report, null, 2));
