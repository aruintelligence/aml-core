import fs from 'node:fs';
import crypto from 'node:crypto';
import { spawnSync } from 'node:child_process';

const sha256 = value => crypto.createHash('sha256').update(value).digest('hex');
const readJson = file => JSON.parse(fs.readFileSync(file, 'utf8'));
function runNode(script, ...args) {
  const r = spawnSync(process.execPath, [script, ...args], { encoding: 'utf8', shell: false });
  if (r.status !== 0) throw new Error(r.stderr || r.stdout || `${script} failed`);
}
function git(...args) {
  const r = spawnSync('git', args, { encoding: 'utf8', shell: false });
  if (r.status !== 0) throw new Error(r.stderr || `git ${args.join(' ')} failed`);
  return r.stdout.trim();
}

const contract = readJson('immutable-release-manifest-contract.json');
const temp = process.env.RUNNER_TEMP || process.cwd();
const transactionPath = `${temp}/aml-manifest-transaction-${process.pid}.json`;
runNode('scripts/build-publication-transaction.mjs', transactionPath);
const tx = readJson(transactionPath);
const manifest = {
  protocol: contract.manifest_protocol,
  package: tx.package,
  version: tx.version,
  dist_tag: tx.dist_tag,
  source: {
    git_tag: tx.source.git_tag,
    git_tag_commit: tx.source.git_tag_commit
  },
  release_sequence: tx.release_sequence,
  release_signing_threshold: tx.release_signing_threshold,
  release_readiness_sha256: tx.release_readiness.sha256,
  release_provenance_root_sha256: tx.release_readiness.release_provenance_root_sha256,
  artifact: {
    sha256: tx.artifact.sha256,
    npm_integrity: tx.artifact.npm_integrity,
    npm_shasum: tx.artifact.npm_shasum
  },
  publication_transaction_root_sha256: tx.transaction_root_sha256,
  claim_boundary: contract.claim_boundary
};
for (const field of contract.required_bindings) {
  const values = {
    package: manifest.package,
    version: manifest.version,
    dist_tag: manifest.dist_tag,
    source_git_tag: manifest.source.git_tag,
    source_git_tag_commit: manifest.source.git_tag_commit,
    release_sequence: manifest.release_sequence,
    release_signing_threshold: manifest.release_signing_threshold,
    release_readiness_sha256: manifest.release_readiness_sha256,
    release_provenance_root_sha256: manifest.release_provenance_root_sha256,
    artifact_sha256: manifest.artifact.sha256,
    artifact_npm_integrity: manifest.artifact.npm_integrity,
    artifact_npm_shasum: manifest.artifact.npm_shasum,
    publication_transaction_root_sha256: manifest.publication_transaction_root_sha256
  };
  if (values[field] === undefined || values[field] === null || values[field] === '') throw new Error(`Missing manifest binding: ${field}`);
}
if (git('rev-parse', `${manifest.source.git_tag}^{commit}`) !== manifest.source.git_tag_commit) throw new Error('Source tag commit drift');
manifest.manifest_root_sha256 = sha256(JSON.stringify(manifest));
const out = `${JSON.stringify(manifest, null, 2)}\n`;
fs.writeFileSync(process.argv[2] || 'aml-immutable-release-manifest.json', out);
try { fs.unlinkSync(transactionPath); } catch {}
process.stdout.write(out);
