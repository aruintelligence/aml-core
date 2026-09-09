import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';

const action = fs.readFileSync('actions/verifier-conformance/action.yml', 'utf8');

test('verifier conformance action exposes portable evidence outputs', () => {
  for (const needle of [
    'witness-record-file:',
    'witness-result:',
    'challenge-sha256:',
    'witness-vector-sha256:',
    'create-witness-record-from-conformance.mjs'
  ]) assert.match(action, new RegExp(needle.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')));
});

test('verifier conformance action routes user-controlled inputs through environment variables', () => {
  for (const needle of [
    'AML_VERIFIER_COMMAND: ${{ inputs.verifier-command }}',
    'AML_SOURCE_URL: ${{ inputs.source-url }}',
    'AML_WITNESS_ID: ${{ inputs.witness-id }}',
    'AML_VERIFIER_NAME: ${{ inputs.verifier-name }}',
    'AML_VERIFIER_RUNTIME: ${{ inputs.runtime }}'
  ]) assert.ok(action.includes(needle), `missing safe env mapping: ${needle}`);

  const runBody = action.slice(action.indexOf('      run: |'));
  assert.equal(runBody.includes('${{ inputs.'), false, 'run script must not interpolate action inputs directly into shell source');
  assert.ok(runBody.includes('"$AML_VERIFIER_COMMAND"'));
  assert.ok(runBody.includes('"$AML_SOURCE_URL"'));
});

test('canonical repository cannot silently manufacture an external witness', () => {
  assert.ok(action.includes('GITHUB_REPOSITORY')); 
  assert.ok(action.includes('aruintelligence/aml-core'));
  assert.ok(action.includes('Skipping external witness generation inside canonical aml-core repository.'));
});
