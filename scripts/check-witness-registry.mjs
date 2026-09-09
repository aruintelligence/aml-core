import fs from 'node:fs';
import process from 'node:process';
import { pathToFileURL } from 'node:url';
import { validateWitnessRecord } from './validate-witness-record.mjs';

export function validateWitnessRegistry(registry) {
  const failures = [];
  const records = Array.isArray(registry?.records) ? registry.records : [];

  if (registry?.schema !== 'aml-witness-registry/1') failures.push('registry schema must be aml-witness-registry/1');
  if (!Array.isArray(registry?.records)) failures.push('registry records must be an array');
  if (registry?.external_witness_count !== records.length) {
    failures.push(`external_witness_count=${registry?.external_witness_count} but records.length=${records.length}`);
  }

  const seenIds = new Set();
  const seenReports = new Set();
  for (const [index, record] of records.entries()) {
    const prefix = `records[${index}]`;
    const result = validateWitnessRecord(record);
    for (const failure of result.failures) failures.push(`${prefix}: ${failure}`);

    if (seenIds.has(record?.witness_id)) failures.push(`${prefix}: duplicate witness_id ${record?.witness_id}`);
    seenIds.add(record?.witness_id);

    if (typeof record?.report_url === 'string' && record.report_url) {
      const normalizedReport = record.report_url.replace(/\/+$/, '').toLowerCase();
      if (seenReports.has(normalizedReport)) failures.push(`${prefix}: duplicate report_url ${record.report_url}`);
      seenReports.add(normalizedReport);
    }
  }

  return {
    verified: failures.length === 0,
    failures,
    external_witness_count: records.length,
    witness_ids: records.map((record) => record?.witness_id).filter(Boolean),
    promise: 'Only records passing the canonical witness validator are counted; canonical aml-core evidence and duplicate report URLs cannot inflate the external witness count.'
  };
}

function main() {
  let registry;
  try {
    registry = JSON.parse(fs.readFileSync('WITNESSES.json', 'utf8'));
  } catch (error) {
    console.error(JSON.stringify({ verified: false, failures: [`unable to read WITNESSES.json: ${error.message}`] }, null, 2));
    process.exit(1);
  }

  const result = validateWitnessRegistry(registry);
  if (!result.verified) {
    console.error(JSON.stringify(result, null, 2));
    process.exit(1);
  }
  console.log(JSON.stringify(result, null, 2));
}

if (process.argv[1] && pathToFileURL(process.argv[1]).href === import.meta.url) main();
