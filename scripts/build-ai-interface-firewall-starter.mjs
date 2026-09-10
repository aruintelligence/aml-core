#!/usr/bin/env node

import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';

const SOURCE_DIR = 'starters/ai-interface-firewall';
const OUTPUT_DIR = process.argv[2] || 'dist/ai-interface-firewall-starter';
const REQUIRED_FILES = ['README.md', 'index.html'];

function sha256(bytes) {
  return crypto.createHash('sha256').update(bytes).digest('hex');
}

function codeUnitCompare(a, b) {
  return a < b ? -1 : a > b ? 1 : 0;
}

function sourceCommit() {
  return process.env.GITHUB_SHA || null;
}

for (const name of REQUIRED_FILES) {
  const source = path.join(SOURCE_DIR, name);
  if (!fs.existsSync(source) || !fs.statSync(source).isFile()) {
    throw new Error(`missing starter source: ${source}`);
  }
}

fs.rmSync(OUTPUT_DIR, { recursive: true, force: true });
fs.mkdirSync(OUTPUT_DIR, { recursive: true });

const files = [];
for (const name of REQUIRED_FILES) {
  const source = path.join(SOURCE_DIR, name);
  const destination = path.join(OUTPUT_DIR, name);
  const bytes = fs.readFileSync(source);
  fs.writeFileSync(destination, bytes);
  files.push({ path: name, bytes: bytes.length, sha256: sha256(bytes) });
}

files.sort((a, b) => codeUnitCompare(a.path, b.path));
const sums = files.map((entry) => `${entry.sha256}  ${entry.path}\n`).join('');
const rootSha256 = sha256(Buffer.from(sums, 'utf8'));

const manifest = {
  schema: 'aml-ai-interface-firewall-starter/1',
  source_directory: SOURCE_DIR,
  source_commit: sourceCommit(),
  file_count: files.length,
  root_algorithm: 'SHA-256 over UTF-8 sorted SHA256SUMS material',
  root_sha256: rootSha256,
  files,
  claim_boundary: 'This artifact binds the exact starter files uploaded by GitHub Actions. It demonstrates a narrow browser integration and does not prove certification, safety, legal compliance, objective wellbeing measurement, or external adoption.'
};

fs.writeFileSync(path.join(OUTPUT_DIR, 'SHA256SUMS'), sums);
fs.writeFileSync(path.join(OUTPUT_DIR, 'manifest.json'), `${JSON.stringify(manifest, null, 2)}\n`);

console.log(JSON.stringify({ valid: true, output: OUTPUT_DIR, ...manifest }, null, 2));
