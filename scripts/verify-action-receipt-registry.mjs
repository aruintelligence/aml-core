#!/usr/bin/env node
// Rebuild and verify the hash-chain index, then replay the source verifiers.
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { canonicalJSONStringify } from '../protocol/canonicalJson.js';

const root = path.resolve(fileURLToPath(new URL('..', import.meta.url)));
const registryPath = 'registry/action-receipts.jsonl';
const registryFile = path.join(root, registryPath);
const sources = JSON.parse(fs.readFileSync(path.join(root, 'registry/action-receipt-sources.json')));
const sha = bytes => crypto.createHash('sha256').update(bytes).digest('hex');
const hash = value => sha(canonicalJSONStringify(value));
const mode = process.argv[2];
if (!['--write', '--check'].includes(mode)) {
  throw new Error('Usage: node scripts/verify-action-receipt-registry.mjs --write|--check [--append-only-base REF]');
}
assert.equal(sources.protocol, 'aml-action-receipt-registry-sources/1');
const entries = [];
const ids = new Set();
let previous = null;
for (const source of sources.sources) {
  assert.ok(/^[a-z_]+$/.test(source.kind));
  assert.ok(!source.path.startsWith('/') && !source.path.includes('..'));
  const bytes = fs.readFileSync(path.join(root, source.path));
  const records = source.path.endsWith('.jsonl') ? bytes.toString('utf8').trimEnd().split('\n').map(JSON.parse) :
    source.collection ? JSON.parse(bytes.toString('utf8'))[source.collection] :
      [JSON.parse(bytes.toString('utf8'))];
  assert.ok(Array.isArray(records));
  assert.equal(records.length, source.count, source.path);
  const fileSha = sha(bytes);
  for (const [index, record] of records.entries()) {
    const { receipt_sha256, ...body } = record;
    assert.equal(receipt_sha256, hash(body), `${source.path}:${index + 1}`);
    const identifier = record.case_id ?? record.pilot_id ?? record.adapter ?? record.protocol;
    const id = `${source.kind}:${identifier}`;
    assert.ok(!ids.has(id), `duplicate registry ID: ${id}`);
    ids.add(id);
    const entryBody = { protocol: 'aml-action-receipt-registry-entry/1', sequence: entries.length + 1,
      id, kind: source.kind, source_path: source.path, source_record: index + 1,
      source_file_sha256: fileSha, receipt_sha256,
      previous_entry_sha256: previous };
    const entry = { ...entryBody, entry_sha256: hash(entryBody) };
    previous = entry.entry_sha256;
    entries.push(entry);
  }
}
const expected = entries.map(x => JSON.stringify(x)).join('\n') + '\n';
if (mode === '--write') {
  if (fs.existsSync(registryFile)) {
    assert.ok(expected.startsWith(fs.readFileSync(registryFile, 'utf8')),
      'existing registry rows are immutable; new receipts must append');
  }
  fs.writeFileSync(registryFile, expected);
} else assert.equal(fs.readFileSync(registryFile, 'utf8'), expected, 'registry does not match sources');

const baseFlag = process.argv.indexOf('--append-only-base');
if (baseFlag >= 0) {
  const ref = process.argv[baseFlag + 1];
  assert.ok(ref && !ref.startsWith('-'));
  const has = execFileSync('git', ['ls-tree', '-r', '--name-only', ref, '--', registryPath],
    { cwd: root, encoding: 'utf8' }).trim();
  const prior = has ? execFileSync('git', ['show', `${ref}:${registryPath}`],
    { cwd: root, encoding: 'utf8' }) : '';
  assert.ok(expected.startsWith(prior), `registry altered or deleted rows from ${ref}`);
}

if (mode === '--check') {
  const commands = [
    ['node', ['scripts/verify-action-boundary-expanded.mjs']],
    ['python3', ['scripts/verify-action-boundary-expanded.py']],
    ['node', ['scripts/verify-action-browser-observation.mjs']],
    ['node', ['scripts/dispatch-controlled-pilot-pages.mjs', '--check']],
    ['node', ['scripts/build-action-site-browser-receipts.mjs', '--check']],
    ['node', ['scripts/build-action-receipt-adapters-report.mjs', '--check']],
    ['node', ['scripts/build-action-stress-375.mjs', '--check']],
    ['python3', ['scripts/verify-action-stress-375.py']],
    ['node', ['scripts/build-action-stress-matrix.mjs', '--check']]
  ];
  for (const [program, args] of commands) {
    execFileSync(program, args, { cwd: root, stdio: 'pipe', maxBuffer: 4 * 1024 * 1024 });
  }
}
console.log(JSON.stringify({ protocol: 'aml-action-receipt-registry-verification/1',
  entries: entries.length, counts: Object.fromEntries(sources.sources.map(s => [s.kind, s.count])),
  root_entry_sha256: previous, registry_file_sha256: sha(expected),
  deep_source_verification: mode === '--check' }));
