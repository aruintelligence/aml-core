import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import { spawnSync } from 'node:child_process';

const sha256 = bytes => crypto.createHash('sha256').update(bytes).digest('hex');
function run(command, args) {
  const r = spawnSync(command, args, { encoding: 'utf8', shell: false });
  if (r.status !== 0) throw new Error(r.stderr || r.stdout || `${command} failed`);
  return r.stdout.trim();
}
const bindingPath = process.argv[2];
if (!bindingPath) throw new Error('usage: verify-artifact-provenance-binding.mjs <binding.json>');
const expected = JSON.parse(fs.readFileSync(bindingPath, 'utf8'));
if (expected.protocol !== 'aml-artifact-provenance-binding/1') throw new Error('unsupported artifact binding protocol');
const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'aml-artifact-verify-'));
const provenancePath = path.join(temp, 'provenance.json');
run(process.execPath, ['scripts/build-release-provenance-evidence.mjs', provenancePath]);
const provenance = JSON.parse(fs.readFileSync(provenancePath, 'utf8'));
const packJson = run(process.platform === 'win32' ? 'npm.cmd' : 'npm', ['pack', '--json', '--pack-destination', temp]);
const packed = JSON.parse(packJson)[0];
const tarballPath = path.join(temp, packed.filename);
const bytes = fs.readFileSync(tarballPath);
const errors = [];
if (expected.package !== provenance.package || expected.version !== provenance.version) errors.push('package identity mismatch');
if (expected.release_provenance?.evidence_root_sha256 !== provenance.evidence_root_sha256) errors.push('provenance root mismatch');
if (expected.release_provenance?.control_commit !== provenance.control_commit) errors.push('control commit mismatch');
if (expected.artifact?.sha256 !== sha256(bytes)) errors.push('tarball SHA-256 mismatch');
if ((expected.artifact?.npm_shasum_sha1 || null) !== (packed.shasum || null)) errors.push('npm shasum mismatch');
if ((expected.artifact?.npm_integrity || null) !== (packed.integrity || null)) errors.push('npm integrity mismatch');
if (errors.length) throw new Error(errors.join('; '));
console.log(JSON.stringify({ valid: true, protocol: 'aml-artifact-provenance-binding-verification/1', package: expected.package, version: expected.version, artifact_sha256: expected.artifact.sha256, evidence_root_sha256: expected.release_provenance.evidence_root_sha256, claim_boundary: 'Project-controlled clean rebuild verification only; not npm registry publication proof or third-party attestation.' }, null, 2));
