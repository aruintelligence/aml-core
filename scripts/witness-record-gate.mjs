#!/usr/bin/env node

import fs from 'node:fs';
import process from 'node:process';
import { validateWitnessRecord } from './validate-witness-record.mjs';

const file = process.argv[2];
if (!file) {
  console.error('Usage: node scripts/witness-record-gate.mjs <witness-record.json>');
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

const outputFile = process.env.GITHUB_OUTPUT;
if (outputFile) {
  const lines = [
    `valid=${result.valid ? 'true' : 'false'}`,
    `witness-id=${result.valid ? result.witness_id : ''}`,
    `result=${result.valid ? result.result : ''}`,
    `source-url=${result.valid ? result.source_url : ''}`
  ];
  fs.appendFileSync(outputFile, `${lines.join('\n')}\n`);
}

process.exit(result.valid ? 0 : 1);
