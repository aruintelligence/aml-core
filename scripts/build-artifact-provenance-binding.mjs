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
const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'aml-artifact-binding-'));
const provenancePath = path.join(temp, 'provenance.json');
run(process.execPath, ['scripts/build-release-provenance-evidence.mjs', provenancePath]);
const provenance = JSON.parse(fs.readFileSync(provenancePath, 'utf8'));
const packJson = run(process.platform === 'win32' ? 'npm.cmd' : 'npm', ['pack', '--json', '--pack-destination', temp]);
const packed = JSON.parse(packJson)[0];
if (!packed?.filename) throw new Error('npm pack did not return artifact metadata');
const tarballPath = path.join(temp, packed.filename);
const bytes = fs.readFileSync(tarballPath);
const report = {
  protocol: 'aml-artifact-provenance-binding/1',
  package: provenance.package,
  version: provenance.version,
  release_provenance: {
    evidence_root_sha256: provenance.evidence_root_sha256,
    control_commit: provenance.control_commit,
    rollback_target: provenance.rollback_target
  },
  artifact: {
    filename: packed.filename,
    bytes: bytes.length,
    sha256: sha256(bytes),
    npm_shasum_sha1: packed.shasum || null,
    npm_integrity: packed.integrity || null
  },
  claim_boundary: 'Project-generated binding between this checkout provenance and the npm-packed tarball bytes. It is not proof that this tarball was published to npm or independently attested.'
};
if (!/^[a-f0-9]{64}$/.test(report.artifact.sha256)) throw new Error('artifact SHA-256 missing');
if (!/^[a-f0-9]{64}$/.test(report.release_provenance.evidence_root_sha256)) throw new Error('provenance root missing');
const out = `${JSON.stringify(report, null, 2)}\n`;
const target = process.argv[2] || 'aml-artifact-provenance-binding.json';
fs.writeFileSync(target, out);
console.log(out.trim());
