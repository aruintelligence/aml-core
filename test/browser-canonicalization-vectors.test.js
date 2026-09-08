import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';

import { canonicalJSONStringifyBrowser, sha256Browser } from '../docs/aml-browser-integrity.js';

const vectors = JSON.parse(fs.readFileSync('protocol/browser-canonicalization-vectors.json', 'utf8'));

test('browser canonicalization matches every published golden vector', async () => {
  assert.equal(vectors.schema, 'aml-browser-canonicalization-vectors/1');
  assert.equal(vectors.canonicalization, 'sorted-json-v1');
  for (const vector of vectors.vectors) {
    assert.equal(canonicalJSONStringifyBrowser(vector.input), vector.canonical, vector.name);
    assert.equal(await sha256Browser(vector.input), vector.sha256, vector.name);
  }
});
