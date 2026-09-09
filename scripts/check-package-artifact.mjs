#!/usr/bin/env node

import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFileSync } from 'node:child_process';

const pkg = JSON.parse(fs.readFileSync('package.json', 'utf8'));
const failures = [];
const checks = [];
const check = (name, ok, detail) => {
  checks.push({ name, ok: Boolean(ok), detail });
  if (!ok) failures.push(`${name}: ${detail}`);
};

let pack;
try {
  const raw = execFileSync('npm', ['pack', '--json', '--dry-run'], { encoding: 'utf8' });
  const parsed = JSON.parse(raw);
  pack = parsed[0];
} catch (error) {
  console.error(JSON.stringify({ valid: false, failures: [`npm pack --dry-run failed: ${error.message}`] }, null, 2));
  process.exit(1);
}

const files = new Set((pack.files || []).map((entry) => entry.path));
const required = new Set([
  pkg.main,
  'package.json',
  'LICENSE',
  'README.md',
  ...Object.values(pkg.bin || {})
].map((p) => String(p).replace(/^\.\//, '')));

check('package name preserved', pack.name === pkg.name, `${pack.name} must equal ${pkg.name}`);
check('package version preserved', pack.version === pkg.version, `${pack.version} must equal ${pkg.version}`);
check('package has files', files.size > 0, 'npm pack produced no files');
for (const requiredPath of required) {
  check(`required artifact ${requiredPath}`, files.has(requiredPath), `${requiredPath} must be included in the tarball`);
}

const forbiddenPatterns = [
  /(^|\/)\.env($|\.)/i,
  /private[-_. ]?key/i,
  /(^|\/)id_(rsa|ed25519)(\.|$)/i,
  /(^|\/).*\.p12$/i,
  /(^|\/).*\.pfx$/i,
  /(^|\/).*\.key$/i,
  /npmrc$/i,
  /(^|\/)secrets?(\/|$)/i
];

const forbidden = [...files].filter((file) => forbiddenPatterns.some((pattern) => pattern.test(file)));
check('no obvious secret/private-key paths', forbidden.length === 0, forbidden.length ? forbidden.join(', ') : 'none');

const pemFiles = [...files].filter((file) => file.endsWith('.pem'));
for (const pemPath of pemFiles) {
  const sourcePath = path.resolve(pemPath);
  if (!fs.existsSync(sourcePath)) continue;
  const text = fs.readFileSync(sourcePath, 'utf8');
  check(
    `PEM ${pemPath} is public-only`,
    !/BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY/.test(text),
    `${pemPath} must not contain private key material`
  );
}

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'aml-package-audit-'));
try {
  const raw = execFileSync('npm', ['pack', '--json', '--pack-destination', tmp], { encoding: 'utf8' });
  const packed = JSON.parse(raw)[0];
  const tarball = path.join(tmp, packed.filename);
  check('tarball created', fs.existsSync(tarball), tarball);

  const installDir = path.join(tmp, 'consumer');
  fs.mkdirSync(installDir, { recursive: true });
  fs.writeFileSync(path.join(installDir, 'package.json'), JSON.stringify({ private: true, type: 'module' }));
  execFileSync('npm', ['install', '--ignore-scripts', tarball], { cwd: installDir, stdio: 'pipe' });

  const importProbe = `import('${pkg.name}').then(m=>{if(!m)process.exit(2)}).catch(e=>{console.error(e);process.exit(1)})`;
  execFileSync(process.execPath, ['-e', importProbe], { cwd: installDir, stdio: 'pipe' });
  check('clean consumer import', true, `import ${pkg.name}`);

  const amlBin = path.join(installDir, 'node_modules', '.bin', process.platform === 'win32' ? 'aml.cmd' : 'aml');
  execFileSync(amlBin, ['validate', path.resolve('examples/simple.aml')], { cwd: installDir, stdio: 'pipe' });
  check('installed aml CLI validates source', true, 'aml validate examples/simple.aml');

  const meaningBin = path.join(installDir, 'node_modules', '.bin', process.platform === 'win32' ? 'aml-meaning.cmd' : 'aml-meaning');
  execFileSync(meaningBin, [path.resolve('examples/simple.aml')], { cwd: installDir, stdio: 'pipe' });
  check('installed aml-meaning CLI fingerprints source', true, 'aml-meaning examples/simple.aml');
} catch (error) {
  failures.push(`clean install/smoke test failed: ${error.message}`);
} finally {
  fs.rmSync(tmp, { recursive: true, force: true });
}

console.log(JSON.stringify({
  valid: failures.length === 0,
  package: { name: pkg.name, version: pkg.version },
  packed_files: files.size,
  packed_bytes: pack.size,
  unpacked_bytes: pack.unpackedSize,
  checks: checks.length,
  failures
}, null, 2));

if (failures.length) process.exit(1);
