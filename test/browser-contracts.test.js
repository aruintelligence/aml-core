import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';

const pageSchema = JSON.parse(fs.readFileSync('protocol/aml-page.schema.json', 'utf8'));
const receiptSchema = JSON.parse(fs.readFileSync('protocol/aml-dom-receipt.schema.json', 'utf8'));
const bootstrap = fs.readFileSync('docs/aml.js', 'utf8');
const live = fs.readFileSync('docs/aml-live.js', 'utf8');

test('AML page manifest schema is versioned and bounded', () => {
  assert.equal(pageSchema.properties.schema.const, 'aml-page/1');
  const item = pageSchema.properties.elements.items;
  assert.deepEqual(item.required, ['selector', 'attention_cost', 'restoration_value']);
  assert.equal(item.properties.attention_cost.minimum, 0);
  assert.equal(item.properties.attention_cost.maximum, 10);
  assert.equal(item.properties.restoration_value.minimum, 0);
  assert.equal(item.properties.restoration_value.maximum, 10);
});

test('AML DOM receipt schema exposes inspectable decision totals', () => {
  assert.equal(receiptSchema.properties.schema.const, 'aml-dom-receipt/1');
  assert.ok(receiptSchema.required.includes('totals'));
  assert.ok(receiptSchema.required.includes('decisions'));
  const totals = receiptSchema.properties.totals.required;
  assert.deepEqual(totals, ['evaluated', 'allowed', 'suppressed', 'errors']);
});

test('one-script browser bootstrap activates all reference browser layers', () => {
  assert.match(bootstrap, /\.\/aml-gate\.js/);
  assert.match(bootstrap, /\.\/aml-live\.js/);
  assert.match(bootstrap, /\.\/aml-page-manifest\.js/);
  assert.match(bootstrap, /aml-browser-bootstrap\/1/);
});

test('live DOM firewall publishes bounded receipt history and ignores its own decision outputs', () => {
  assert.match(live, /__AML_RECEIPT_HISTORY__/);
  assert.match(live, /length > 50/);
  assert.match(live, /attributeFilter: WATCHED_ATTRIBUTES/);
  assert.doesNotMatch(live, /WATCHED_ATTRIBUTES[\s\S]*data-aml-decision/);
});
