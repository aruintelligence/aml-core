#!/usr/bin/env node

import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import process from 'node:process';
import { pathToFileURL } from 'node:url';

const FORBIDDEN_SOURCE_EXTENSIONS = new Set([
  '.js', '.mjs', '.cjs', '.ts', '.tsx', '.jsx', '.py', '.go', '.rs', '.java', '.kt', '.kts', '.cs', '.c', '.cc', '.cpp', '.h', '.hpp', '.swift', '.zig', '.rb', '.php', '.sh', '.bash', '.ps1'
]);

function sha256(bytes) {
  return crypto.createHash('sha256').update(bytes).digest('hex');
}

function walk(root, current = root) {
  const files = [];
  for (const entry of fs.readdirSync(current, { withFileTypes: true })) {
    const full = path.join(current, entry.name);
    if (entry.isDirectory()) files.push(...walk(root, full));
    else if (entry.isFile()) files.push(path.relative(root, full).split(path.sep).join('/'));
  }
  return files.sort();
}

export function checkExternalVerifierKit(root = 'dist/external-verifier-kit') {
  const failures = [];
  const manifestPath = path.join(root, 'manifest.json');
  const sumsPath = path.join(root, 'SHA256SUMS');
  if (!fs.existsSync(manifestPath)) return { valid: false, failures: ['manifest.json missing'] };
  if (!fs.existsSync(sumsPath)) return { valid: false, failures: ['SHA256SUMS missing'] };

  let manifest;
  try {
    manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
  } catch (error) {
    return { valid: false, failures: [`manifest.json invalid: ${error.message}`] };
  }

  if (manifest.schema !== 'aml-external-verifier-kit/1') failures.push('invalid kit schema');
  if (manifest.reference_code_included !== false) failures.push('reference_code_included must be false');
  if (!Array.isArray(manifest.files)) failures.push('manifest files must be an array');
  const entries = Array.isArray(manifest.files) ? manifest.files : [];
  if (manifest.file_count !== entries.length) failures.push('file_count does not match manifest files');

  const seen = new Set();
  for (const entry of entries) {
    if (!entry || typeof entry.path !== 'string') {
      failures.push('invalid manifest file entry');
      continue;
    }
    if (seen.has(entry.path)) failures.push(`duplicate manifest path: ${entry.path}`);
    seen.add(entry.path);
    if (entry.path.startsWith('/') || entry.path.includes('..') || entry.path.includes('\\')) failures.push(`unsafe path: ${entry.path}`);
    if (FORBIDDEN_SOURCE_EXTENSIONS.has(path.extname(entry.path).toLowerCase())) failures.push(`reference source code path included: ${entry.path}`);
    const full = path.join(root, entry.path);
    if (!fs.existsSync(full) || !fs.statSync(full).isFile()) {
      failures.push(`manifest file missing: ${entry.path}`);
      continue;
    }
    const bytes = fs.readFileSync(full);
    if (bytes.length !== entry.bytes) failures.push(`byte size mismatch: ${entry.path}`);
    if (sha256(bytes) !== entry.sha256) failures.push(`SHA-256 mismatch: ${entry.path}`);
  }

  const actualFiles = walk(root).filter((file) => !['manifest.json', 'SHA256SUMS'].includes(file));
  const declaredFiles = [...seen].sort();
  if (JSON.stringify(actualFiles) !== JSON.stringify(declaredFiles)) failures.push('artifact file set does not exactly match manifest');

  const sums = entries
    .slice()
    .sort((a, b) => a.path < b.path ? -1 : a.path > b.path ? 1 : 0)
    .map((entry) => `${entry.sha256}  ${entry.path}\n`)
    .join('');
  if (fs.readFileSync(sumsPath, 'utf8') !== sums) failures.push('SHA256SUMS does not match manifest entries');
  if (sha256(Buffer.from(sums, 'utf8')) !== manifest.root_sha256) failures.push('kit root SHA-256 mismatch');

  const required = [
    'README.md',
    'conformance/verifier-challenge.json',
    'independent/python/witness-vector.json',
    'protocol/sorted-json-v1.md',
    'protocol/aml-witness-bundle.schema.json',
    'protocol/aml-witness-record.schema.json'
  ];
  for (const requiredPath of required) if (!seen.has(requiredPath)) failures.push(`required kit file missing: ${requiredPath}`);

  const challengePath = path.join(root, 'conformance/verifier-challenge.json');
  if (fs.existsSync(challengePath)) {
    try {
      const challenge = JSON.parse(fs.readFileSync(challengePath, 'utf8'));
      if (!challenge.witness_vector || !seen.has(challenge.witness_vector)) failures.push('challenge witness_vector does not resolve inside kit');
    } catch (error) {
      failures.push(`challenge JSON invalid: ${error.message}`);
    }
  }

  return { valid: failures.length === 0, failures, file_count: entries.length, root_sha256: manifest.root_sha256 || null };
}

function main() {
  const root = process.argv[2] || 'dist/external-verifier-kit';
  const result = checkExternalVerifierKit(root);
  console.log(JSON.stringify(result, null, 2));
  process.exit(result.valid ? 0 : 1);
}

if (process.argv[1] && pathToFileURL(process.argv[1]).href === import.meta.url) main();
