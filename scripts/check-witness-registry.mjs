import fs from 'node:fs';
import { validateWitnessRecord } from './validate-witness-record.mjs';

const registry = JSON.parse(fs.readFileSync('WITNESSES.json', 'utf8'));
const failures = [];
const records = Array.isArray(registry.records) ? registry.records : [];

if (registry.schema !== 'aml-witness-registry/1') failures.push('registry schema must be aml-witness-registry/1');
if (registry.external_witness_count !== records.length) {
  failures.push(`external_witness_count=${registry.external_witness_count} but records.length=${records.length}`);
}

const seen = new Set();
for (const [index, record] of records.entries()) {
  const prefix = `records[${index}]`;
  const result = validateWitnessRecord(record);
  for (const failure of result.failures) failures.push(`${prefix}: ${failure}`);
  if (seen.has(record?.witness_id)) failures.push(`${prefix}: duplicate witness_id ${record?.witness_id}`);
  seen.add(record?.witness_id);
}

if (failures.length) {
  console.error(JSON.stringify({ verified: false, failures }, null, 2));
  process.exit(1);
}

console.log(JSON.stringify({
  verified: true,
  external_witness_count: records.length,
  witness_ids: records.map((record) => record.witness_id),
  promise: 'Only records passing the canonical witness validator are counted; aml-core-owned evidence cannot inflate the external witness count.'
}, null, 2));
