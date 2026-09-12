import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';

const readJson = file => JSON.parse(fs.readFileSync(file, 'utf8'));
function run(command, args, options = {}) {
  return spawnSync(command, args, { encoding: 'utf8', shell: false, ...options });
}
function must(command, args, options = {}) {
  const r = run(command, args, options);
  if (r.status !== 0) throw new Error(r.stderr || r.stdout || `${command} ${args.join(' ')} failed`);
  return r.stdout.trim();
}
const npm = process.platform === 'win32' ? 'npm.cmd' : 'npm';
const contract = readJson('release-integrity-contract.json');
const publication = readJson('publication-contract.json');
const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'aml-live-integrity-'));
const manifestPath = path.join(temp, 'manifest.json');
must(process.execPath, ['scripts/build-immutable-release-manifest.mjs', manifestPath]);
const manifest = readJson(manifestPath);
const target = `${manifest.package}@${manifest.version}`;
const view = run(npm, ['view', target, 'version', '--json']);
if (view.status !== 0) {
  const output = `${view.stderr || ''}${view.stdout || ''}`;
  if (contract.monitoring.unpublished_state_is_inactive_not_passing && /E404|404 Not Found|is not in this registry/i.test(output)) {
    console.log(JSON.stringify({
      protocol: 'aml-live-release-integrity-monitor/1',
      status: 'inactive_unpublished',
      package: manifest.package,
      version: manifest.version,
      passed: false,
      claim_boundary: 'The stable target is not observable in the configured npm registry. This is inactive monitoring state, not a passing integrity result.'
    }, null, 2));
    process.exit(0);
  }
  throw new Error(output || 'npm registry query failed');
}
const observedVersion = JSON.parse(view.stdout);
const observedTag = must(npm, ['view', manifest.package, `dist-tags.${manifest.dist_tag}`, '--json']);
const observedIntegrity = must(npm, ['view', target, 'dist.integrity', '--json']);
const observedShasum = must(npm, ['view', target, 'dist.shasum', '--json']);
const parseScalar = text => { try { return JSON.parse(text); } catch { return text.trim(); } };
const registry = {
  version: observedVersion,
  dist_tag: parseScalar(observedTag),
  integrity: parseScalar(observedIntegrity),
  shasum: parseScalar(observedShasum)
};
if (registry.version !== manifest.version) throw new Error('Registry version drift');
if (registry.dist_tag !== manifest.version) throw new Error('Registry dist-tag drift');
if (registry.integrity !== manifest.artifact.npm_integrity) throw new Error('Registry integrity drift');
if (registry.shasum !== manifest.artifact.npm_shasum) throw new Error('Registry shasum drift');
const consumer = path.join(temp, 'consumer');
fs.mkdirSync(consumer);
must(npm, ['init', '-y'], { cwd: consumer });
must(npm, ['install', '--ignore-scripts', '--no-audit', '--no-fund', target], { cwd: consumer });
const importCheck = run(process.execPath, ['--input-type=module', '-e', `const m=await import('${manifest.package}'); if(!m) process.exit(2);`], { cwd: consumer });
if (importCheck.status !== 0) throw new Error(importCheck.stderr || 'Installed API import failed');
const cli = process.platform === 'win32' ? path.join(consumer, 'node_modules', '.bin', 'aml.cmd') : path.join(consumer, 'node_modules', '.bin', 'aml');
const cliCheck = run(cli, ['version'], { cwd: consumer });
if (cliCheck.status !== 0) throw new Error(cliCheck.stderr || cliCheck.stdout || 'Installed CLI smoke test failed');
console.log(JSON.stringify({
  protocol: 'aml-live-release-integrity-monitor/1',
  status: 'verified_live_registry',
  registry: publication.registry,
  package: manifest.package,
  version: manifest.version,
  dist_tag: manifest.dist_tag,
  manifest_root_sha256: manifest.manifest_root_sha256,
  checks: {
    registry_version_matches: true,
    dist_tag_matches: true,
    integrity_matches: true,
    shasum_matches: true,
    clean_install_passes: true,
    api_import_passes: true,
    cli_smoke_test_passes: true
  },
  passed: true
}, null, 2));
