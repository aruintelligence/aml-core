#!/usr/bin/env node

import fs from 'node:fs';
import process from 'node:process';
import { pathToFileURL } from 'node:url';

const REQUIRED = [
  'schema', 'witness_id', 'observed_at', 'source_url',
  'artifact_type', 'result', 'external_to_aml_core', 'summary'
];
const ALLOWED = new Set([
  ...REQUIRED,
  'artifact_hash', 'verifier', 'runtime', 'report_url', 'notes'
]);
const RESULTS = new Set(['PASS', 'FAIL', 'MIXED']);
const WITNESS_ID = /^[a-z0-9][a-z0-9._-]{2,127}$/;
const ISO_TIME = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z$/;
const SHA256 = /^[0-9a-f]{64}$/;
const EXTERNAL_VERIFIER_CHALLENGE = 'aml-external-verifier-challenge/1';

function publicHttpsUrl(value, field, failures) {
  if (typeof value !== 'string' || value.length < 8) {
    failures.push(`${field} must be a public https URL`);
    return null;
  }
  let parsed;
  try {
    parsed = new URL(value);
  } catch {
    failures.push(`${field} must be a valid URL`);
    return null;
  }
  if (parsed.protocol !== 'https:') failures.push(`${field} must use https`);
  const host = parsed.hostname.toLowerCase();
  if (!host || host === 'localhost' || host.endsWith('.localhost')) {
    failures.push(`${field} must be publicly addressable`);
  }
  return parsed;
}

function isCanonicalAmlCoreSource(parsed) {
  if (!parsed) return false;
  const host = parsed.hostname.toLowerCase();
  const path = parsed.pathname.replace(/\/+$/, '').toLowerCase();
  if (host === 'github.com' || host === 'www.github.com' || host === 'raw.githubusercontent.com') {
    return path.startsWith('/aruintelligence/aml-core');
  }
  if (host === 'aruintelligence.github.io') return path.startsWith('/aml-core');
  return false;
}

export function validateWitnessRecord(record) {
  const failures = [];
  if (!record || typeof record !== 'object' || Array.isArray(record)) {
    return { valid: false, failures: ['record must be a JSON object'] };
  }

  for (const field of REQUIRED) {
    if (!(field in record)) failures.push(`${field} is required`);
  }
  for (const key of Object.keys(record)) {
    if (!ALLOWED.has(key)) failures.push(`unexpected property: ${key}`);
  }

  if (record.schema !== 'aml-witness-record/1') failures.push('schema must be aml-witness-record/1');
  if (typeof record.witness_id !== 'string' || !WITNESS_ID.test(record.witness_id)) {
    failures.push('witness_id must match ^[a-z0-9][a-z0-9._-]{2,127}$');
  }
  if (typeof record.observed_at !== 'string' || !ISO_TIME.test(record.observed_at) || !Number.isFinite(Date.parse(record.observed_at))) {
    failures.push('observed_at must be a valid UTC ISO-8601 timestamp ending in Z');
  }

  const sourceUrl = publicHttpsUrl(record.source_url, 'source_url', failures);
  if (isCanonicalAmlCoreSource(sourceUrl)) {
    failures.push('source_url must be maintained outside the canonical aruintelligence/aml-core evidence surfaces');
  }

  if (typeof record.artifact_type !== 'string' || !record.artifact_type.trim()) failures.push('artifact_type is required');
  if (!RESULTS.has(record.result)) failures.push('result must be PASS, FAIL, or MIXED');
  if (record.external_to_aml_core !== true) failures.push('external_to_aml_core must be true');
  if (typeof record.summary !== 'string' || !record.summary.trim()) failures.push('summary is required');

  if (record.artifact_hash !== undefined && record.artifact_hash !== null && typeof record.artifact_hash !== 'string') {
    failures.push('artifact_hash must be a string or null');
  }
  if (record.artifact_type === EXTERNAL_VERIFIER_CHALLENGE && !SHA256.test(String(record.artifact_hash || ''))) {
    failures.push('artifact_hash must be the lowercase SHA-256 of the exact external verifier challenge bytes');
  }
  for (const field of ['verifier', 'runtime']) {
    if (record[field] !== undefined && record[field] !== null && typeof record[field] !== 'string') {
      failures.push(`${field} must be a string or null`);
    }
  }
  if (record.report_url !== undefined && record.report_url !== null) {
    const reportUrl = publicHttpsUrl(record.report_url, 'report_url', failures);
    if (isCanonicalAmlCoreSource(reportUrl)) {
      failures.push('report_url must not point to the canonical aml-core repository or Pages site');
    }
  }
  if (record.notes !== undefined) {
    if (!Array.isArray(record.notes) || record.notes.length > 20 || record.notes.some((note) => typeof note !== 'string')) {
      failures.push('notes must be an array of at most 20 strings');
    }
  }

  return {
    valid: failures.length === 0,
    failures,
    witness_id: typeof record.witness_id === 'string' ? record.witness_id : null,
    result: RESULTS.has(record.result) ? record.result : null,
    source_url: sourceUrl?.href || null,
    artifact_hash: SHA256.test(String(record.artifact_hash || '')) ? record.artifact_hash : null,
    acceptance_boundary: 'Syntax, exact challenge hashing for verifier-challenge records, and canonical-source exclusion are machine-checkable. Independent maintenance and truth of the external report still require human/public-evidence review.'
  };
}

function main() {
  const file = process.argv[2];
  if (!file) {
    console.error('Usage: node scripts/validate-witness-record.mjs <witness-record.json>');
    process.exit(2);
  }
  let record;
  try {
    record = JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch (error) {
    console.error(JSON.stringify({ valid: false, failures: [`unable to read/parse record: ${error.message}`] }, null, 2));
    process.exit(2);
  }
  const result = validateWitnessRecord(record);
  console.log(JSON.stringify(result, null, 2));
  process.exit(result.valid ? 0 : 1);
}

if (process.argv[1] && pathToFileURL(process.argv[1]).href === import.meta.url) main();
