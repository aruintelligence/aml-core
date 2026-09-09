#!/usr/bin/env node

import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { execFileSync } from 'node:child_process';

const pkg = JSON.parse(fs.readFileSync('package.json', 'utf8'));
const outputDir = path.resolve(process.argv[2] || 'artifacts/npm');

execFileSync(process.execPath, ['scripts/check-package-artifact.mjs'], { stdio: 'inherit' });

fs.rmSync(outputDir, { recursive: true, force: true });
fs.mkdirSync(outputDir, { recursive: true });

const raw = execFileSync('npm', ['pack', '--json', '--pack-destination', outputDir], { encoding: 'utf8' });
const packed = JSON.parse(raw)[0];
if (!packed?.filename) throw new Error('npm pack did not return a filename');

const tarballPath = path.join(outputDir, packed.filename);
const bytes = fs.readFileSync(tarballPath);
const sha256 = crypto.createHash('sha256').update(bytes).digest('hex');

const manifest = {
  schema: 'aml-npm-artifact/1',
  package: {
    name: pkg.name,
    version: pkg.version,
    filename: packed.filename,
    sha256,
    bytes: bytes.length
  },
  repository: pkg.repository?.url || null,
  source_commit: process.env.GITHUB_SHA || null,
  generated_by: 'scripts/build-package-artifact.mjs',
  verification: {
    prepublish_audit: 'scripts/check-package-artifact.mjs',
    clean_consumer_install: true,
    api_import_smoke_test: true,
    aml_cli_smoke_test: true,
    aml_meaning_cli_smoke_test: true,
    aml_release_quorum_cli_smoke_test: true,
    aml_release_profile_cli_smoke_test: true
  },
  boundary: 'This manifest proves the uploaded tarball bytes match this SHA-256 and passed the repository package audit. It is not an npm registry publication, external adoption claim, or package-ownership proof.'
};

fs.writeFileSync(
  path.join(outputDir, 'aml-npm-artifact.json'),
  `${JSON.stringify(manifest, null, 2)}\n`
);
fs.writeFileSync(
  path.join(outputDir, `${packed.filename}.sha256`),
  `${sha256}  ${packed.filename}\n`
);

console.log(JSON.stringify({ valid: true, output_dir: outputDir, ...manifest }, null, 2));
