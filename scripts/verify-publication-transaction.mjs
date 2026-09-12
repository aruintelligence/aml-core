import fs from 'node:fs';
import crypto from 'node:crypto';
import { spawnSync } from 'node:child_process';

function sha256(bytes) { return crypto.createHash('sha256').update(bytes).digest('hex'); }
function readJson(file) { return JSON.parse(fs.readFileSync(file, 'utf8')); }
function fail(message) { console.error(message); process.exit(1); }
function git(...args) {
  const run = spawnSync('git', args, { encoding: 'utf8', shell: false });
  if (run.status !== 0) fail(run.stderr || `git ${args.join(' ')} failed`);
  return run.stdout.trim();
}

const target = process.argv[2] || 'aml-publication-transaction.json';
const tx = readJson(target);
const contract = readJson('publication-contract.json');
const pkg = readJson('package.json');
const signing = readJson('release-signing-policy.json');
if (tx.protocol !== 'aml-publication-transaction/1') fail('Unexpected publication transaction protocol');
if (tx.package !== pkg.name || tx.version !== pkg.version) fail('Transaction package identity mismatch');
if (tx.registry !== contract.registry || tx.dist_tag !== contract.stable.dist_tag) fail('Registry or dist-tag mismatch');
if (tx.release_sequence !== signing.freshness.current_release_sequence) fail('Release sequence mismatch');
if (tx.release_signing_threshold !== signing.authorization.production_threshold) fail('Release signing threshold mismatch');
if (tx.source.git_tag !== contract.stable.git_tag) fail('Stable git tag mismatch');
if (tx.source.git_tag_commit !== git('rev-parse', `${contract.stable.git_tag}^{commit}`)) fail('Stable tag commit mismatch');
const copy = structuredClone(tx);
delete copy.transaction_root_sha256;
if (sha256(JSON.stringify(copy)) !== tx.transaction_root_sha256) fail('Publication transaction root mismatch');
for (const p of contract.required_preconditions) if (!tx.preconditions.includes(p)) fail(`Missing publication precondition: ${p}`);
for (const p of contract.postconditions) if (!tx.postconditions.includes(p)) fail(`Missing publication postcondition: ${p}`);
console.log(JSON.stringify({ valid: true, protocol: 'aml-publication-transaction-verification/1', transaction_root_sha256: tx.transaction_root_sha256, package: tx.package, version: tx.version, dist_tag: tx.dist_tag, claim_boundary: 'Project-controlled verification of publication intent and bound evidence only; not proof that npm publication occurred.' }, null, 2));
