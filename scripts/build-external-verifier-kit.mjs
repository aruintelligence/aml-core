#!/usr/bin/env node

import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { execFileSync } from 'node:child_process';

export const KIT_FILES = [
  'conformance/verifier-challenge.json',
  'conformance/witness-record.example.json',
  'independent/python/witness-vector.json',
  'protocol/sorted-json-v1.md',
  'protocol/browser-canonicalization-vectors.json',
  'protocol/test-vectors.json',
  'protocol/verification-contract-v1.json',
  'protocol/verification-contract-v2.json',
  'protocol/verification-contract-catalog.json',
  'protocol/verification-contract-lineage.json',
  'protocol/migrations/aml-verifier-contract-2026-09-08-01_to_2026-09-09-01.json',
  'protocol/aml-verification-contract-snapshot.schema.json',
  'protocol/aml-verification-contract-migration.schema.json',
  'protocol/verification-report-vectors.json',
  'protocol/aml-browser-evidence.schema.json',
  'protocol/aml-dom-receipt.schema.json',
  'protocol/aml-session-attestation.schema.json',
  'protocol/aml-verification-challenge.schema.json',
  'protocol/aml-verification-report.schema.json',
  'protocol/aml-verifier-conformance-result.schema.json',
  'protocol/aml-witness-bundle.schema.json',
  'protocol/aml-witness-record.schema.json',
  'protocol/aml-verifier-cli.md',
  'protocol/VERIFIER_CONTRACT_VERSIONING.md',
  'publications/EXTERNAL_VERIFIER_CHALLENGE.md',
  'publications/WITNESS_SUBMISSION.md'
].sort();

const FORBIDDEN_SOURCE_EXTENSIONS = new Set([
  '.js', '.mjs', '.cjs', '.ts', '.tsx', '.jsx', '.py', '.go', '.rs', '.java', '.kt', '.kts', '.cs', '.c', '.cc', '.cpp', '.h', '.hpp', '.swift', '.zig', '.rb', '.php', '.sh', '.bash', '.ps1'
]);

function sha256(bytes) {
  return crypto.createHash('sha256').update(bytes).digest('hex');
}

function codeUnitCompare(a, b) {
  return a < b ? -1 : a > b ? 1 : 0;
}

function currentCommit() {
  if (process.env.GITHUB_SHA) return process.env.GITHUB_SHA;
  try {
    return execFileSync('git', ['rev-parse', 'HEAD'], { encoding: 'utf8' }).trim();
  } catch {
    return null;
  }
}

export function buildExternalVerifierKit(outputDir = 'dist/external-verifier-kit') {
  for (const source of KIT_FILES) {
    if (!fs.existsSync(source) || !fs.statSync(source).isFile()) throw new Error(`missing kit source: ${source}`);
    const ext = path.extname(source).toLowerCase();
    if (FORBIDDEN_SOURCE_EXTENSIONS.has(ext)) throw new Error(`reference source code is forbidden in external verifier kit: ${source}`);
  }

  const catalog = JSON.parse(fs.readFileSync('protocol/verification-contract-catalog.json', 'utf8'));
  const currentSnapshot = (catalog.snapshots || []).find((entry) => entry.snapshot_id === catalog.current_snapshot);
  if (!currentSnapshot?.manifest || !currentSnapshot?.source_commit) throw new Error('current verifier snapshot is not resolvable from catalog');

  const challengeBytes = fs.readFileSync('conformance/verifier-challenge.json');
  const witnessVectorBytes = fs.readFileSync('independent/python/witness-vector.json');

  fs.rmSync(outputDir, { recursive: true, force: true });
  fs.mkdirSync(outputDir, { recursive: true });

  const entries = [];
  for (const source of KIT_FILES) {
    const bytes = fs.readFileSync(source);
    const destination = path.join(outputDir, source);
    fs.mkdirSync(path.dirname(destination), { recursive: true });
    fs.writeFileSync(destination, bytes);
    entries.push({ path: source, bytes: bytes.length, sha256: sha256(bytes) });
  }
  entries.sort((a, b) => codeUnitCompare(a.path, b.path));

  const readme = `# ĀML External Verifier Kit\n\nThis artifact is intentionally **reference-code-free**. It contains the current and historical verifier-contract snapshots, explicit migration lineage, public protocol text, JSON Schemas, canonicalization/test vectors, the black-box verifier challenge, one JSON witness fixture, and witness-submission material. It does not contain the JavaScript, Python, Go, or other reference verifier implementations from aml-core.\n\nCurrent verifier snapshot: **${catalog.current_snapshot}**\nMigration count: **${(catalog.migrations || []).length}**\n\nImplement the published contract in your own runtime, then run the External Verifier Challenge from your own repository. PASS, FAIL, and MIXED results are all useful.\n\nCommand contract:\n\n\`\`\`text\n<verifier-command> --now <ISO-8601> <bundle.json>\n\`\`\`\n\nA valid bundle must emit JSON with \`valid: true\` and exit 0. Invalid challenge cases must be rejected with a nonzero exit. Snapshot 2 conformance results identify the exact challenge and golden witness-vector bytes by SHA-256.\n\nThis kit reduces accidental dependence on reference implementation code. Possessing or using the kit does not itself prove an implementation is independent.\n`;
  const readmeBytes = Buffer.from(readme, 'utf8');
  fs.writeFileSync(path.join(outputDir, 'README.md'), readmeBytes);
  entries.push({ path: 'README.md', bytes: readmeBytes.length, sha256: sha256(readmeBytes) });
  entries.sort((a, b) => codeUnitCompare(a.path, b.path));

  const rootMaterial = entries.map((entry) => `${entry.sha256}  ${entry.path}\n`).join('');
  const kitRoot = sha256(Buffer.from(rootMaterial, 'utf8'));
  const manifest = {
    schema: 'aml-external-verifier-kit/1',
    source_commit: currentCommit(),
    reference_code_included: false,
    current_contract_snapshot_id: catalog.current_snapshot,
    current_contract_source_commit: currentSnapshot.source_commit,
    contract_snapshot_count: (catalog.snapshots || []).length,
    contract_migration_count: (catalog.migrations || []).length,
    challenge_sha256: sha256(challengeBytes),
    witness_vector_sha256: sha256(witnessVectorBytes),
    file_count: entries.length,
    root_algorithm: 'SHA-256 over UTF-8 sorted SHA256SUMS material',
    root_sha256: kitRoot,
    files: entries,
    claim_boundary: 'The kit binds an exact reference-code-free contract package. It does not prove implementation independence, correctness, certification, standards approval, safety, ethics, legal compliance, or adoption.'
  };
  fs.writeFileSync(path.join(outputDir, 'manifest.json'), `${JSON.stringify(manifest, null, 2)}\n`);
  fs.writeFileSync(path.join(outputDir, 'SHA256SUMS'), rootMaterial);
  return { outputDir, manifest };
}

if (import.meta.url === new URL(process.argv[1], 'file:').href) {
  const output = process.argv[2] || 'dist/external-verifier-kit';
  const result = buildExternalVerifierKit(output);
  console.log(JSON.stringify({ valid: true, output: result.outputDir, ...result.manifest }, null, 2));
}
