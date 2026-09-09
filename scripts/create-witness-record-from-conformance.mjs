#!/usr/bin/env node

import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import process from 'node:process';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { validateWitnessRecord } from './validate-witness-record.mjs';

const scriptDir = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(scriptDir, '..');
const challengePath = path.join(repoRoot, 'conformance/verifier-challenge.json');
const challenge = JSON.parse(fs.readFileSync(challengePath, 'utf8'));
const witnessVectorPath = path.join(repoRoot, challenge.witness_vector);

function sha256File(file) {
  return crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex');
}

const canonicalChallengeSha256 = sha256File(challengePath);
const canonicalWitnessVectorSha256 = sha256File(witnessVectorPath);

function parseArgs(argv) {
  const options = {};
  for (let i = 0; i < argv.length; i += 1) {
    const token = argv[i];
    if (!token.startsWith('--')) throw new Error(`unexpected argument: ${token}`);
    const key = token.slice(2);
    const value = argv[i + 1];
    if (!value || value.startsWith('--')) throw new Error(`missing value for --${key}`);
    options[key] = value;
    i += 1;
  }
  return options;
}

function loadResult(file) {
  let result;
  try {
    result = JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch (error) {
    throw new Error(`unable to read conformance result: ${error.message}`);
  }
  if (!result || typeof result !== 'object' || Array.isArray(result)) throw new Error('conformance result must be a JSON object');
  if (result.schema !== 'aml-verifier-conformance-result/1') throw new Error('unsupported conformance result schema');
  if (result.challenge_schema !== 'aml-external-verifier-challenge/1') throw new Error('unsupported challenge schema');
  if (result.challenge_sha256 !== canonicalChallengeSha256) throw new Error('conformance result challenge hash does not match this checkout');
  if (result.witness_vector_sha256 !== canonicalWitnessVectorSha256) throw new Error('conformance result witness-vector hash does not match this checkout');
  if (!Array.isArray(result.results) || result.results.length === 0) throw new Error('conformance result must contain case results');
  for (const item of result.results) {
    if (!item || typeof item !== 'object' || typeof item.id !== 'string' || typeof item.passed !== 'boolean') {
      throw new Error('conformance result contains malformed case result');
    }
  }
  const allPassed = result.results.every((item) => item.passed === true);
  if (result.passed !== allPassed) throw new Error('conformance result top-level passed flag disagrees with case results');
  return result;
}

export function classifyConformanceResult(result) {
  const passedCases = result.results.filter((item) => item.passed === true).length;
  if (passedCases === result.results.length && result.passed === true) return 'PASS';
  if (passedCases === 0) return 'FAIL';
  return 'MIXED';
}

export function createWitnessRecordFromConformance({
  result,
  witnessId,
  sourceUrl,
  verifier = null,
  runtime = null,
  reportUrl = null,
  observedAt = new Date().toISOString(),
  summary = null
}) {
  if (!result || !Array.isArray(result.results)) throw new Error('validated conformance result is required');
  const resultClass = classifyConformanceResult(result);
  const passedCases = result.results.filter((item) => item.passed === true).length;
  const totalCases = result.results.length;
  const record = {
    schema: 'aml-witness-record/1',
    witness_id: witnessId,
    observed_at: observedAt,
    source_url: sourceUrl,
    artifact_type: 'aml-external-verifier-challenge/1',
    artifact_hash: result.challenge_sha256,
    verifier,
    runtime,
    result: resultClass,
    external_to_aml_core: true,
    summary: summary || `External verifier conformance result: ${resultClass} (${passedCases}/${totalCases} challenge cases matched expected verdicts).`,
    report_url: reportUrl,
    notes: [
      `conformance_result_schema=${result.schema}`,
      `challenge_sha256=${result.challenge_sha256}`,
      `witness_vector_sha256=${result.witness_vector_sha256}`,
      `passed_cases=${passedCases}`,
      `total_cases=${totalCases}`
    ]
  };
  const validation = validateWitnessRecord(record);
  if (!validation.valid) throw new Error(`generated witness record failed validation: ${validation.failures.join('; ')}`);
  return record;
}

export function generateWitnessRecordFile({ resultFile, outputFile, ...options }) {
  const result = loadResult(resultFile);
  const record = createWitnessRecordFromConformance({ result, ...options });
  fs.mkdirSync(path.dirname(path.resolve(outputFile)), { recursive: true });
  fs.writeFileSync(outputFile, `${JSON.stringify(record, null, 2)}\n`);
  return record;
}

function main() {
  let options;
  try {
    options = parseArgs(process.argv.slice(2));
    for (const required of ['result', 'output', 'witness-id', 'source-url']) {
      if (!options[required]) throw new Error(`--${required} is required`);
    }
    const record = generateWitnessRecordFile({
      resultFile: options.result,
      outputFile: options.output,
      witnessId: options['witness-id'],
      sourceUrl: options['source-url'],
      verifier: options.verifier || null,
      runtime: options.runtime || null,
      reportUrl: options['report-url'] || null,
      observedAt: options['observed-at'] || new Date().toISOString(),
      summary: options.summary || null
    });
    console.log(JSON.stringify({ valid: true, output: options.output, result: record.result, witness_id: record.witness_id }, null, 2));
  } catch (error) {
    console.error(JSON.stringify({ valid: false, error: error.message }, null, 2));
    process.exit(1);
  }
}

if (process.argv[1] && pathToFileURL(process.argv[1]).href === import.meta.url) main();
