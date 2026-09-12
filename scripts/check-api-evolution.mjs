import fs from 'node:fs';
import crypto from 'node:crypto';

function fail(message) {
  console.error(message);
  process.exit(1);
}

const stability = JSON.parse(fs.readFileSync('api-stability.json', 'utf8'));
const snapshot = JSON.parse(fs.readFileSync('api-surface.snapshot.json', 'utf8'));
const deprecations = JSON.parse(fs.readFileSync('api-deprecations.json', 'utf8'));
const project = JSON.parse(fs.readFileSync('project-contract.json', 'utf8'));

if (stability.protocol !== 'aml-api-stability/1') fail('Unsupported API stability protocol');
if (snapshot.protocol !== 'aml-api-surface-snapshot/1') fail('Unsupported API snapshot protocol');
if (deprecations.protocol !== 'aml-api-deprecations/1') fail('Unsupported API deprecation protocol');
if (stability.package !== snapshot.package || stability.package !== deprecations.package) fail('API contract package identity drift');

const protectedExports = stability.protected_exports || [];
if (!Array.isArray(protectedExports) || protectedExports.length === 0) fail('Protected API surface must not be empty');
if (new Set(protectedExports).size !== protectedExports.length) fail('Protected API surface contains duplicates');
if (snapshot.protected_export_count !== protectedExports.length) fail('Protected API snapshot count drift');

const material = `${protectedExports.join('\n')}\n`;
const digest = crypto.createHash('sha256').update(material).digest('hex');
if (snapshot.protected_exports_sha256 !== digest) fail(`Protected API snapshot hash drift: ${digest}`);

const entries = deprecations.entries || [];
if (!Array.isArray(entries)) fail('API deprecations entries must be an array');
const names = new Set();
for (const entry of entries) {
  if (!entry || typeof entry !== 'object') fail('Invalid API deprecation entry');
  if (!protectedExports.includes(entry.export)) fail(`Deprecation names unprotected export: ${entry.export}`);
  if (names.has(entry.export)) fail(`Duplicate API deprecation entry: ${entry.export}`);
  names.add(entry.export);
  if (!entry.since) fail(`Deprecation missing since version: ${entry.export}`);
  if (!entry.replacement && !entry.reason) fail(`Deprecation requires replacement or reason: ${entry.export}`);
  if (entry.removal_version && !/^\d+\.\d+\.\d+/.test(entry.removal_version)) fail(`Invalid removal version: ${entry.export}`);
}

const stableMajor = Number(project.release.stableVersion.split('.')[0]);
for (const entry of entries) {
  if (!entry.removal_version) continue;
  const removalMajor = Number(entry.removal_version.split('.')[0]);
  if (!(removalMajor > stableMajor)) fail(`Protected removal must target a SemVer major after stable ${project.release.stableVersion}: ${entry.export}`);
}

process.stdout.write(`${JSON.stringify({
  protocol: 'aml-api-evolution-verification/1',
  valid: true,
  package: stability.package,
  protected_export_count: protectedExports.length,
  protected_exports_sha256: digest,
  deprecation_count: entries.length,
  stable_version: project.release.stableVersion,
  claim_boundary: 'Project-controlled compatibility guard; not an external compatibility certification.'
}, null, 2)}\n`);
