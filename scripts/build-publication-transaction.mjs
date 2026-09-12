import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import { spawnSync } from 'node:child_process';

function sha256(bytes) { return crypto.createHash('sha256').update(bytes).digest('hex'); }
function runNode(script, ...args) {
  const run = spawnSync(process.execPath, [script, ...args], { encoding: 'utf8', shell: false });
  if (run.status !== 0) throw new Error(`${script} failed: ${run.stderr || run.stdout}`);
}
function git(...args) {
  const run = spawnSync('git', args, { encoding: 'utf8', shell: false });
  if (run.status !== 0) throw new Error(run.stderr || `git ${args.join(' ')} failed`);
  return run.stdout.trim();
}
const readJson = file => JSON.parse(fs.readFileSync(file, 'utf8'));

const contract = readJson('publication-contract.json');
const pkg = readJson('package.json');
const signing = readJson('release-signing-policy.json');
const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'aml-publication-'));
const bindingPath = path.join(temp, 'artifact-binding.json');
const readinessPath = path.join(temp, 'release-readiness.json');
runNode('scripts/build-artifact-provenance-binding.mjs', bindingPath);
runNode('scripts/release-readiness-bundle.mjs', readinessPath);
const bindingBytes = fs.readFileSync(bindingPath);
const readinessBytes = fs.readFileSync(readinessPath);
const binding = JSON.parse(bindingBytes.toString('utf8'));
const readiness = JSON.parse(readinessBytes.toString('utf8'));

if (contract.package !== pkg.name || contract.stable.version !== pkg.version) throw new Error('Publication contract package/version mismatch');
if (signing.authorization.production_threshold < 2) throw new Error('Production release signing threshold must be at least 2');
const tagCommit = git('rev-parse', `${contract.stable.git_tag}^{commit}`);
const artifact = binding.artifact || binding.tgz || binding.package || {};
const provenanceRoot = binding.release_provenance_root_sha256 || binding.provenance_root_sha256 || binding.release_provenance?.evidence_root_sha256 || null;
const transaction = {
  protocol: 'aml-publication-transaction/1',
  package: pkg.name,
  version: pkg.version,
  registry: contract.registry,
  dist_tag: contract.stable.dist_tag,
  source: {
    git_tag: contract.stable.git_tag,
    git_tag_commit: tagCommit,
    checkout_commit: git('rev-parse', 'HEAD')
  },
  release_sequence: signing.freshness.current_release_sequence,
  release_signing_threshold: signing.authorization.production_threshold,
  release_readiness: {
    sha256: sha256(readinessBytes),
    contract_root_sha256: readiness.contract_root_sha256,
    release_provenance_root_sha256: readiness.release_provenance?.evidence_root_sha256 || null
  },
  artifact: {
    binding_sha256: sha256(bindingBytes),
    provenance_root_sha256: provenanceRoot,
    filename: artifact.filename || null,
    bytes: artifact.bytes || null,
    sha256: artifact.sha256 || null,
    npm_integrity: artifact.npm_integrity || artifact.integrity || null,
    npm_shasum_sha1: artifact.npm_shasum_sha1 || artifact.npm_shasum || artifact.shasum || null
  },
  preconditions: contract.required_preconditions,
  postconditions: contract.postconditions,
  rollback: contract.rollback,
  claim_boundary: contract.claim_boundary
};
if (!/^[a-f0-9]{64}$/.test(transaction.artifact.sha256 || '')) throw new Error('Packed artifact SHA-256 missing');
if (!transaction.artifact.npm_integrity) throw new Error('Packed artifact npm integrity missing');
if (!/^[a-f0-9]{40}$/.test(transaction.artifact.npm_shasum_sha1 || '')) throw new Error('Packed artifact npm shasum missing');
if (transaction.artifact.provenance_root_sha256 !== transaction.release_readiness.release_provenance_root_sha256) throw new Error('Artifact and readiness provenance roots disagree');
transaction.transaction_root_sha256 = sha256(JSON.stringify(transaction));
const output = `${JSON.stringify(transaction, null, 2)}\n`;
fs.writeFileSync(process.argv[2] || 'aml-publication-transaction.json', output);
process.stdout.write(output);
