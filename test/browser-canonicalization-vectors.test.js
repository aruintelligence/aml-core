import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';

import { canonicalJSONStringifyBrowser, sealBrowserReceipt, sha256Browser,
  verifyBrowserReceipt } from '../docs/aml-browser-integrity.js';
import { canonicalJSONStringify } from '../protocol/canonicalJson.js';

const vectors = JSON.parse(fs.readFileSync('protocol/browser-canonicalization-vectors.json', 'utf8'));

test('browser canonicalization matches every published golden vector', async () => {
  assert.equal(vectors.schema, 'aml-browser-canonicalization-vectors/1');
  assert.equal(vectors.canonicalization, 'sorted-json-v1');
  for (const vector of vectors.vectors) {
    assert.equal(canonicalJSONStringifyBrowser(vector.input), vector.canonical, vector.name);
    assert.equal(canonicalJSONStringify(vector.input), vector.canonical, vector.name);
    assert.equal(await sha256Browser(vector.input), vector.sha256, vector.name);
  }
});

test('a literal __proto__ data key is bound to the browser receipt hash', async () => {
  const metadata = JSON.parse('{"__proto__":{"approved":false},"label":"item"}');
  const receipt = await sealBrowserReceipt({ schema: 'aml-dom-receipt/1', metadata });
  assert.equal((await verifyBrowserReceipt(receipt)).valid, true);
  assert.equal(Object.hasOwn(metadata, '__proto__'), true);
  metadata.__proto__.approved = true;
  const changed = await verifyBrowserReceipt(receipt);
  assert.equal(changed.valid, false);
  assert.equal(changed.reason, 'AML_BROWSER_RECEIPT_HASH_MISMATCH');
});
