#!/usr/bin/env node
import fs from 'node:fs';

const args = process.argv.slice(2);
const get = name => {
  const i = args.indexOf(`--${name}`);
  return i >= 0 ? args[i + 1] : null;
};

const required = ['implementation-id', 'implementation-version', 'runtime', 'source-url', 'command'];
const missing = required.filter(name => !get(name));
if (missing.length) {
  console.error(`missing required flags: ${missing.map(x => `--${x}`).join(', ')}`);
  process.exit(2);
}

const snapshotPath = get('snapshot') || 'protocol/verification-contract-v1.json';
const snapshot = JSON.parse(fs.readFileSync(snapshotPath, 'utf8'));
const external = get('external') === 'true';

const claim = {
  schema: 'aml-verifier-implementation-claim/1',
  prototype: true,
  implementation_id: get('implementation-id'),
  implementation_version: get('implementation-version'),
  runtime: get('runtime'),
  source_url: get('source-url'),
  contract_snapshot_id: snapshot.snapshot_id,
  contract_source_commit: snapshot.source_commit,
  artifact_types: ['aml-witness-bundle/1'],
  conformance_command: get('command'),
  conformance_result_url: get('result-url'),
  external_to_aml_core: external,
  claim_boundary: external
    ? 'Self-declared external implementation claim bound to a specific AML verifier contract snapshot. External status and conformance evidence still require public verification.'
    : 'AML-maintained reference implementation claim. It does not count as an external witness or independent institution.'
};

console.log(JSON.stringify(claim, null, 2));
