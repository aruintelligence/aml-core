import fs from 'node:fs';
import { spawnSync } from 'node:child_process';

function run(command, args) {
  const r = spawnSync(command, args, { encoding: 'utf8', shell: false });
  if (r.status !== 0) throw new Error(r.stderr || r.stdout || `${command} failed`);
  return r.stdout.trim();
}
const bindingPath = process.argv[2];
if (!bindingPath) throw new Error('usage: verify-public-npm-binding.mjs <binding.json>');
const binding = JSON.parse(fs.readFileSync(bindingPath, 'utf8'));
if (binding.protocol !== 'aml-artifact-provenance-binding/1') throw new Error('unsupported artifact binding protocol');
const npm = process.platform === 'win32' ? 'npm.cmd' : 'npm';
const target = `${binding.package}@${binding.version}`;
let dist;
try {
  dist = JSON.parse(run(npm, ['view', target, 'dist', '--json']));
} catch (error) {
  throw new Error(`public npm publication is not verifiable for ${target}: ${error.message || error}`);
}
const errors = [];
if (!dist || typeof dist !== 'object') errors.push('registry dist metadata missing');
if (dist?.integrity !== binding.artifact.npm_integrity) errors.push('registry integrity does not match bound artifact');
if (dist?.shasum !== binding.artifact.npm_shasum_sha1) errors.push('registry shasum does not match bound artifact');
if (errors.length) throw new Error(errors.join('; '));
console.log(JSON.stringify({ valid: true, protocol: 'aml-public-npm-binding-verification/1', package: binding.package, version: binding.version, npm_integrity: dist.integrity, npm_shasum_sha1: dist.shasum, evidence_root_sha256: binding.release_provenance.evidence_root_sha256, claim_boundary: 'Live registry metadata matched the project-bound artifact metadata at verification time. This is not independent certification or proof of downstream installation success.' }, null, 2));
