import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';

const challenge = JSON.parse(fs.readFileSync('conformance/verifier-challenge.json', 'utf8'));
const harness = fs.readFileSync('scripts/run-verifier-conformance.mjs', 'utf8');
const action = fs.readFileSync('actions/verifier-conformance/action.yml', 'utf8');

test('external verifier challenge publishes the exact harness cases', () => {
  assert.equal(challenge.schema, 'aml-external-verifier-challenge/1');
  assert.deepEqual(
    challenge.cases.map((entry) => [entry.id, entry.expected_valid]),
    [
      ['golden-valid', true],
      ['tampered-purpose', false],
      ['tampered-challenge', false],
      ['expired-challenge', false]
    ]
  );
  for (const entry of challenge.cases) {
    assert.match(harness, new RegExp(`id: ['\"]${entry.id}['\"]`));
  }
});

test('external verifier action drives the canonical black-box harness', () => {
  assert.match(action, /verifier-command:/);
  assert.match(action, /scripts\/run-verifier-conformance\.mjs/);
  assert.match(action, /aml-verifier-conformance-result\.json/);
  assert.match(action, /outputs:/);
  assert.match(action, /passed:/);
});

test('external verifier action does not smuggle in a repository verifier', () => {
  const forbidden = [
    'independent/python/verify_witness.py',
    'independent/go/verify.sh',
    'bin/aml.js',
    'aml verify',
    'verifyWitnessBundle',
    'verifyExecutionReceipt'
  ];
  for (const token of forbidden) {
    assert.equal(action.includes(token), false, `external action must not reference ${token}`);
  }
});

test('challenge keeps external witness credit separate from conformance pass', () => {
  assert.equal(challenge.independence.required_for_external_witness_credit, true);
  assert.equal(challenge.independence.must_be_maintained_outside_canonical_repository, true);
  assert.equal(challenge.independence.must_not_import_reference_implementation, true);
  assert.equal(challenge.independence.must_not_wrap_aml_core_cli_or_api, true);
  assert.match(challenge.claim_boundary, /not certification/i);
});
