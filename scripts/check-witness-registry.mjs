import fs from 'node:fs';

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
  if (record?.schema !== 'aml-witness-record/1') failures.push(`${prefix}: invalid schema`);
  if (!record?.witness_id) failures.push(`${prefix}: witness_id required`);
  if (seen.has(record?.witness_id)) failures.push(`${prefix}: duplicate witness_id ${record?.witness_id}`);
  seen.add(record?.witness_id);
  if (record?.external_to_aml_core !== true) failures.push(`${prefix}: external_to_aml_core must be true`);
  if (!['PASS', 'FAIL', 'MIXED'].includes(record?.result)) failures.push(`${prefix}: result must be PASS, FAIL, or MIXED`);
  if (!record?.source_url || !/^https?:\/\//.test(record.source_url)) failures.push(`${prefix}: public http(s) source_url required`);
  if (!record?.summary) failures.push(`${prefix}: summary required`);

  const source = String(record?.source_url || '').toLowerCase();
  if (source.includes('github.com/aruintelligence/aml-core') || source.includes('aruintelligence.github.io/aml-core')) {
    failures.push(`${prefix}: aml-core-owned source cannot be counted as an external witness`);
  }
}

if (failures.length) {
  console.error(JSON.stringify({ verified: false, failures }, null, 2));
  process.exit(1);
}

console.log(JSON.stringify({
  verified: true,
  external_witness_count: records.length,
  witness_ids: records.map((record) => record.witness_id),
  promise: 'Only explicitly external public witness records are counted; aml-core-owned evidence cannot inflate the external witness count.'
}, null, 2));
