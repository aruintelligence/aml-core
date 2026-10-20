#!/usr/bin/env node
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { canonicalJSONStringify } from '../protocol/canonicalJson.js';

const root = path.resolve(fileURLToPath(new URL('..', import.meta.url)));
const hash = bytes => crypto.createHash('sha256').update(bytes).digest('hex');
const files = [
  'CITATION.cff', 'package.json', 'LICENSE',
  'protocol/canonicalJson.js', 'protocol/action-boundary-evidence-receipt.schema.json',
  'protocol/action-receipt-registry-entry.schema.json',
  'conformance/action-boundary-expanded-cases.json',
  'conformance/action-boundary-expanded-receipts.jsonl',
  'conformance/action-stress-375-cases.json',
  'conformance/action-stress-375-receipts.jsonl',
  'pilots/action-boundary/boundary.mjs',
  'pilots/action-boundary/challenge-python-adapter.py',
  'pilots/action-boundary/perl_boundary.pl',
  'pilots/action-boundary/openssl_python_boundary.py',
  'pilots/action-boundary/controlled-sites.json',
  'pilots/action-boundary/receipt-adapters.mjs',
  'docs/action-webcrypto-boundary.js', 'docs/action-browser-matrix.html',
  'docs/action-browser-cases.json', 'docs/action-boundary-expanded-report.json',
  'docs/action-five-runtime-report.json', 'docs/evidence/aml-action-browser-100.json',
  'docs/action-stress-five-runtime-report.json',
  'docs/evidence/aml-action-browser-100.jpg',
  'docs/action-pilots/README.md', 'docs/action-pilots/dispatch-receipts.jsonl',
  'docs/action-receipt-adapters-report.json',
  'docs/action-receipt-revocation-report.json',
  'registry/action-receipt-sources.json', 'registry/action-receipts.jsonl', 'registry/README.md',
  'scripts/build-action-boundary-expanded.mjs',
  'scripts/verify-action-boundary-expanded.mjs',
  'scripts/verify-action-boundary-expanded.py',
  'scripts/build-action-five-runtime-report.mjs',
  'scripts/build-action-stress-375.mjs',
  'scripts/build-action-stress-matrix.mjs',
  'scripts/verify-action-stress-375.py',
  'scripts/verify-action-browser-observation.mjs',
  'scripts/build-controlled-pilot-pages.mjs',
  'scripts/dispatch-controlled-pilot-pages.mjs',
  'scripts/build-action-site-browser-receipts.mjs',
  'scripts/build-action-receipt-adapters-report.mjs',
  'scripts/build-action-revocation-report.mjs',
  'scripts/verify-action-receipt-registry.mjs',
  'scripts/build-action-release-manifest.mjs',
  'test/action-boundary-expanded.test.js', 'test/action-five-runtime.test.js',
  'test/action-browser-observation.test.js',
  'test/action-controlled-site-pilots.test.js',
  'test/action-site-browser-evidence.test.js',
  'test/action-receipt-adapters.test.js',
  'publications/ACTION_BOUNDARY_EXPANDED_CHALLENGE.md',
  'publications/ACTION_BOUNDARY_FIVE_RUNTIME.md',
  'publications/ACTION_BOUNDARY_CONTROLLED_PILOTS.md',
  'publications/ACTION_BOUNDARY_STRESS_375.md',
  'publications/ACTION_RECEIPT_ADAPTERS.md',
  'publications/ACTION_RECEIPT_REVOCATION.md',
  'publications/ACTION_BOUNDARY_PROGRESS.md',
  'reproduction/action-boundary/SPEC.md',
  'reproduction/action-boundary/REPRODUCE.md',
  'reproduction/action-boundary/reproduce.sh'
];
for (const dir of ['docs/action-pilots/before', 'docs/action-pilots/after', 'docs/action-pilots/evidence']) {
  files.push(...fs.readdirSync(path.join(root, dir)).map(name => `${dir}/${name}`));
}
const unique = [...new Set(files)].sort();
assert.equal(unique.length, files.length, 'duplicate manifest path');
const records = unique.map(relative => {
  const bytes = fs.readFileSync(path.join(root, relative));
  return { path: relative, bytes: bytes.length, sha256: hash(bytes) };
});
const body = { protocol: 'aml-action-boundary-release-manifest/1',
  source: 'aruintelligence/aml-core', file_count: records.length,
  expected: { challenge_cases: 475, maintained_bindings: 5, controlled_pages: 10,
    adapter_kinds: 4, registry_receipts: 504 },
  files: records,
  claim_boundary: 'File hashes and Git source are reproducibility metadata, not a DOI or an independent witness.' };
const output = JSON.stringify({ ...body, manifest_sha256: hash(canonicalJSONStringify(body)) }, null, 2) + '\n';
const manifest = path.join(root, 'reproduction/action-boundary/manifest.json');
const mode = process.argv[2];
if (mode === '--write') fs.writeFileSync(manifest, output);
else if (mode === '--check') assert.equal(fs.readFileSync(manifest, 'utf8'), output);
else throw Error('Usage: node scripts/build-action-release-manifest.mjs --write|--check');
console.log(JSON.stringify({ files: records.length, manifest_sha256: hash(canonicalJSONStringify(body)),
  registry_sha256: records.find(x => x.path === 'registry/action-receipts.jsonl').sha256 }));
