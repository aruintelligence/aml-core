#!/usr/bin/env node

import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import process from 'node:process';
import { pathToFileURL } from 'node:url';
import { readRegularFile } from '../tooling/readRegularFile.js';
import { commandAuthorizationDecision, withCommandAuthorization, commandOutcome, diagnosticOnlyRequested,
  AML_DIAGNOSTIC_ONLY_FLAG } from '../runtime/commandAuthorization.js';

// Authorized only when the kit is consistent and its root SHA-256 equals a
// root the relying party pinned (--expected-root-sha256). Without a pin the
// check is consistency-only: exit 3, or 0 under --diagnostic-only.
const KIT_REQUIRED = ['kit_valid', 'root_pinned'];
const KIT_DENIALS = { kit_valid: 'AML_AUTHZ_KIT_NOT_VALID', root_pinned: 'AML_AUTHZ_KIT_ROOT_NOT_PINNED' };
const KIT_TRUST = ['the expected root SHA-256 was obtained from an independently trusted source'];

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
    if (entry.path.startsWith('/') || entry.path.includes('..') || entry.path.includes('\\')) {
      failures.push(`unsafe path: ${entry.path}`);
      continue; // Reject before any filesystem access derived from this path.
    }
    if (FORBIDDEN_SOURCE_EXTENSIONS.has(path.extname(entry.path).toLowerCase())) failures.push(`reference source code path included: ${entry.path}`);
    const full = path.join(root, entry.path);
    let bytes;
    try { bytes = readRegularFile(full, { maxBytes: 16 * 1024 * 1024, noFollow: true }); }
    catch {
      failures.push(`manifest file missing or unreadable: ${entry.path}`);
      continue;
    }
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
    'protocol/aml-witness-record.schema.json',
    'protocol/verification-contract-v1.json',
    'protocol/verification-contract-v2.json',
    'protocol/verification-contract-catalog.json',
    'protocol/verification-contract-lineage.json',
    'protocol/migrations/aml-verifier-contract-2026-09-08-01_to_2026-09-09-01.json'
  ];
  for (const requiredPath of required) if (!seen.has(requiredPath)) failures.push(`required kit file missing: ${requiredPath}`);

  const challengePath = path.join(root, 'conformance/verifier-challenge.json');
  const vectorPath = path.join(root, 'independent/python/witness-vector.json');
  const catalogPath = path.join(root, 'protocol/verification-contract-catalog.json');
  const lineagePath = path.join(root, 'protocol/verification-contract-lineage.json');
  if (fs.existsSync(challengePath)) {
    try {
      const challengeBytes = fs.readFileSync(challengePath);
      const challenge = JSON.parse(challengeBytes.toString('utf8'));
      if (!challenge.witness_vector || !seen.has(challenge.witness_vector)) failures.push('challenge witness_vector does not resolve inside kit');
      if (manifest.challenge_sha256 !== sha256(challengeBytes)) failures.push('manifest challenge_sha256 mismatch');
    } catch (error) {
      failures.push(`challenge JSON invalid: ${error.message}`);
    }
  }
  if (fs.existsSync(vectorPath) && manifest.witness_vector_sha256 !== sha256(fs.readFileSync(vectorPath))) {
    failures.push('manifest witness_vector_sha256 mismatch');
  }

  if (fs.existsSync(catalogPath) && fs.existsSync(lineagePath)) {
    try {
      const catalog = JSON.parse(fs.readFileSync(catalogPath, 'utf8'));
      const lineage = JSON.parse(fs.readFileSync(lineagePath, 'utf8'));
      const current = (catalog.snapshots || []).find((entry) => entry.snapshot_id === catalog.current_snapshot);
      if (manifest.current_contract_snapshot_id !== catalog.current_snapshot) failures.push('manifest current contract snapshot does not match bundled catalog');
      if (manifest.current_contract_source_commit !== current?.source_commit) failures.push('manifest current contract source commit does not match bundled catalog');
      if (manifest.contract_snapshot_count !== (catalog.snapshots || []).length) failures.push('manifest contract_snapshot_count mismatch');
      if (manifest.contract_migration_count !== (catalog.migrations || []).length) failures.push('manifest contract_migration_count mismatch');
      if ((lineage.nodes || []).length !== manifest.contract_snapshot_count) failures.push('bundled lineage node count does not match manifest snapshot count');
      if ((lineage.edges || []).length !== manifest.contract_migration_count) failures.push('bundled lineage edge count does not match manifest migration count');
    } catch (error) {
      failures.push(`bundled contract catalog/lineage invalid: ${error.message}`);
    }
  }

  return {
    valid: failures.length === 0,
    failures,
    file_count: entries.length,
    root_sha256: manifest.root_sha256 || null,
    current_contract_snapshot_id: manifest.current_contract_snapshot_id || null,
    challenge_sha256: manifest.challenge_sha256 || null,
    witness_vector_sha256: manifest.witness_vector_sha256 || null
  };
}

function main() {
  const diagnosticOnly = diagnosticOnlyRequested(process.argv);
  const args = process.argv.slice(2).filter(arg => arg !== AML_DIAGNOSTIC_ONLY_FLAG);
  const pinIndex = args.indexOf('--expected-root-sha256');
  const expectedRoot = pinIndex >= 0 ? args[pinIndex + 1] ?? null : null;
  if (pinIndex >= 0) args.splice(pinIndex, 2);
  const root = args[0] || 'dist/external-verifier-kit';
  const verification = checkExternalVerifierKit(root);
  const result = withCommandAuthorization(verification, commandAuthorizationDecision({
    kit_valid: verification.valid === true,
    root_pinned: typeof expectedRoot === 'string' && /^[a-f0-9]{64}$/.test(expectedRoot) &&
      verification.root_sha256 === expectedRoot
  }, KIT_REQUIRED, KIT_DENIALS), KIT_TRUST);
  const { output, exitCode } = commandOutcome(result, { diagnosticOnly, invalidCode: 1 });
  console.log(JSON.stringify(output, null, 2));
  process.exit(exitCode);
}

if (process.argv[1] && pathToFileURL(process.argv[1]).href === import.meta.url) main();
