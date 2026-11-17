#!/usr/bin/env node

import fs from 'node:fs';
import process from 'node:process';
import { witnessRecordCommandResult } from './validate-witness-record.mjs';
import { commandOutcome, diagnosticOnlyRequested, AML_DIAGNOSTIC_ONLY_FLAG,
  AML_NOT_AN_AUTHORIZATION_DECISION } from '../runtime/commandAuthorization.js';

// Exit 0 only when authorized; a witness record never is (human review is
// required), so a valid record exits 3 unless --diagnostic-only is requested.
const diagnosticOnly = diagnosticOnlyRequested(process.argv);
const file = process.argv.slice(2).filter(arg => arg !== AML_DIAGNOSTIC_ONLY_FLAG)[0];
if (!file) {
  console.error('Usage: node scripts/witness-record-gate.mjs <witness-record.json> [--diagnostic-only]');
  process.exit(2);
}

let record;
try {
  record = JSON.parse(fs.readFileSync(file, 'utf8'));
} catch (error) {
  console.error(JSON.stringify({ valid: false, authorized: false, failures: [`unable to read/parse record: ${error.message}`] }, null, 2));
  process.exit(2);
}

const result = witnessRecordCommandResult(record);
const { output, exitCode } = commandOutcome(result, { diagnosticOnly, invalidCode: 1 });
console.log(JSON.stringify(output, null, 2));

const outputFile = process.env.GITHUB_OUTPUT;
if (outputFile) {
  const consistent = result.valid === true;
  const lines = [
    `valid=${consistent ? 'true' : 'false'}`,
    `authorized=false`,
    `decision-use=${AML_NOT_AN_AUTHORIZATION_DECISION}`,
    `witness-id=${consistent ? result.witness_id : ''}`,
    `result=${consistent ? result.result : ''}`,
    `source-url=${consistent ? result.source_url : ''}`
  ];
  fs.appendFileSync(outputFile, `${lines.join('\n')}\n`);
}

process.exit(exitCode);
