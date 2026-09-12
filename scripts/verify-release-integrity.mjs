import fs from 'node:fs';
import crypto from 'node:crypto';
import { spawnSync } from 'node:child_process';

const sha256 = value => crypto.createHash('sha256').update(value).digest('hex');
const readJson = file => JSON.parse(fs.readFileSync(file, 'utf8'));
function git(...args) {
  const r = spawnSync('git', args, { encoding: 'utf8', shell: false });
  if (r.status !== 0) throw new Error(r.stderr || `git ${args.join(' ')} failed`);
  return r.stdout.trim();
}

const contract = readJson('release-integrity-contract.json');
const manifestContract = readJson('immutable-release-manifest-contract.json');
const manifest = readJson(process.argv[2] || 'aml-immutable-release-manifest.json');
if (manifest.protocol !== manifestContract.manifest_protocol) throw new Error('Manifest protocol mismatch');
const root = manifest.manifest_root_sha256;
const copy = structuredClone(manifest);
delete copy.manifest_root_sha256;
if (sha256(JSON.stringify(copy)) !== root) throw new Error('Manifest root tamper');
if (git('rev-parse', `${manifest.source.git_tag}^{commit}`) !== manifest.source.git_tag_commit) throw new Error('Source tag commit drift');
if (manifest.dist_tag !== contract.stable_channel) throw new Error('Stable channel drift');
if (!/^[a-f0-9]{64}$/.test(manifest.artifact.sha256)) throw new Error('Artifact SHA-256 invalid');
if (!manifest.artifact.npm_integrity || !manifest.artifact.npm_shasum) throw new Error('Registry artifact identity incomplete');
console.log(JSON.stringify({ protocol: 'aml-release-integrity-verification/1', passed: true, manifest_root_sha256: root }, null, 2));
