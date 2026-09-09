import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { validateWitnessRecord } from '../scripts/validate-witness-record.mjs';

function validRecord(overrides = {}) {
  return {
    schema: 'aml-witness-record/1',
    witness_id: 'outside-go-verifier-001',
    observed_at: '2026-09-09T07:15:00Z',
    source_url: 'https://github.com/example-labs/aml-verifier',
    artifact_type: 'aml-external-verifier-challenge/1',
    artifact_hash: null,
    verifier: 'example-go-verifier',
    runtime: 'go1.24',
    result: 'PASS',
    external_to_aml_core: true,
    summary: 'Independent black-box verifier matched the published challenge cases.',
    report_url: 'https://github.com/example-labs/aml-verifier/actions/runs/123',
    notes: [],
    ...overrides
  };
}

test('external witness validator accepts a well-formed outside PASS record', () => {
  const result = validateWitnessRecord(validRecord());
  assert.equal(result.valid, true);
  assert.equal(result.witness_id, 'outside-go-verifier-001');
  assert.equal(result.result, 'PASS');
});

test('external witness validator treats FAIL and MIXED as first-class results', () => {
  assert.equal(validateWitnessRecord(validRecord({ result: 'FAIL' })).valid, true);
  assert.equal(validateWitnessRecord(validRecord({ result: 'MIXED' })).valid, true);
});

test('canonical aml-core evidence cannot self-inflate the external witness registry', () => {
  for (const source_url of [
    'https://github.com/aruintelligence/aml-core/issues/56',
    'https://raw.githubusercontent.com/aruintelligence/aml-core/main/WITNESSES.json',
    'https://aruintelligence.github.io/aml-core/proof.html'
  ]) {
    const result = validateWitnessRecord(validRecord({ source_url }));
    assert.equal(result.valid, false, source_url);
    assert.ok(result.failures.some((failure) => failure.includes('outside the canonical')));
  }
});

test('self-declaring external status is insufficient when the public source is canonical', () => {
  const result = validateWitnessRecord(validRecord({
    external_to_aml_core: true,
    source_url: 'https://github.com/aruintelligence/aml-core'
  }));
  assert.equal(result.valid, false);
});

test('witness validator fails closed on malformed time, result, URL, and unknown fields', () => {
  assert.equal(validateWitnessRecord(validRecord({ observed_at: 'yesterday' })).valid, false);
  assert.equal(validateWitnessRecord(validRecord({ result: 'SUCCESS' })).valid, false);
  assert.equal(validateWitnessRecord(validRecord({ source_url: 'http://example.com/report' })).valid, false);
  assert.equal(validateWitnessRecord(validRecord({ surprise: true })).valid, false);
});

test('canonical report URL is rejected even when the source repository is external', () => {
  const result = validateWitnessRecord(validRecord({
    report_url: 'https://github.com/aruintelligence/aml-core/actions/runs/1'
  }));
  assert.equal(result.valid, false);
  assert.ok(result.failures.some((failure) => failure.includes('report_url')));
});

test('witness action exposes only validated fields', () => {
  const action = fs.readFileSync('actions/witness-record/action.yml', 'utf8');
  assert.match(action, /scripts\/witness-record-gate\.mjs/);
  assert.match(action, /steps\.validate\.outputs\.witness-id/);
  assert.match(action, /steps\.validate\.outputs\.result/);
  assert.doesNotMatch(action, /WITNESSES\.json/);
});

test('external verifier issue form uses the witness registry result vocabulary', () => {
  const form = fs.readFileSync('.github/ISSUE_TEMPLATE/external-verifier-report.yml', 'utf8');
  assert.match(form, /- PASS/);
  assert.match(form, /- FAIL/);
  assert.match(form, /- MIXED/);
  assert.doesNotMatch(form, /DISAGREES WITH REFERENCE/);
  assert.doesNotMatch(form, /COULD NOT COMPLETE/);
  assert.match(form, /aml-witness-record\/1 JSON/);
});
