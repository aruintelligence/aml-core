import fs from 'node:fs';
import crypto from 'node:crypto';
import { spawnSync } from 'node:child_process';

function fail(message) {
  console.error(message);
  process.exit(1);
}

const policy = JSON.parse(fs.readFileSync('package-content-policy.json', 'utf8'));
const pkg = JSON.parse(fs.readFileSync('package.json', 'utf8'));
if (policy.protocol !== 'aml-package-content-policy/1') fail('Unsupported package content policy');
if (policy.package !== pkg.name) fail('Package identity drift in package content policy');

const packed = spawnSync('npm', ['pack', '--json', '--dry-run', '--ignore-scripts'], { encoding: 'utf8', shell: process.platform === 'win32' });
if (packed.status !== 0) fail(`npm pack --dry-run failed: ${packed.stderr || packed.stdout}`);
let report;
try {
  report = JSON.parse(packed.stdout);
} catch (error) {
  fail(`Unable to parse npm pack JSON: ${error.message}`);
}
if (!Array.isArray(report) || !report[0] || !Array.isArray(report[0].files)) fail('Unexpected npm pack JSON shape');

const paths = report[0].files.map(file => file.path).sort();
const pathSet = new Set(paths);
for (const required of policy.required_files || []) {
  if (!pathSet.has(required)) fail(`Required package file missing: ${required}`);
}
for (const file of paths) {
  if ((policy.forbidden_exact || []).includes(file)) fail(`Forbidden package file: ${file}`);
  if ((policy.forbidden_suffixes || []).some(suffix => file.toLowerCase().endsWith(suffix.toLowerCase()))) fail(`Forbidden package suffix: ${file}`);
  if ((policy.forbidden_fragments || []).some(fragment => file.toLowerCase().includes(fragment.toLowerCase()))) fail(`Forbidden package filename fragment: ${file}`);
}

const files = paths.map(file => {
  if (!fs.existsSync(file) || !fs.statSync(file).isFile()) fail(`npm pack listed missing/non-file path: ${file}`);
  const bytes = fs.readFileSync(file);
  return {
    path: file,
    size: bytes.length,
    sha256: crypto.createHash('sha256').update(bytes).digest('hex')
  };
});
const rootMaterial = files.map(file => `${file.path}\t${file.size}\t${file.sha256}`).join('\n') + '\n';
const contentRoot = crypto.createHash('sha256').update(rootMaterial).digest('hex');
const manifest = {
  protocol: 'aml-package-content-manifest/1',
  package: pkg.name,
  version: pkg.version,
  file_count: files.length,
  content_root_sha256: contentRoot,
  files,
  claim_boundary: 'Deterministic manifest of files selected by npm pack in this checkout; not proof that npm registry publication occurred.'
};

const output = process.argv[2];
const json = `${JSON.stringify(manifest, null, 2)}\n`;
if (output) fs.writeFileSync(output, json);
else process.stdout.write(json);
