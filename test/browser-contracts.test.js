import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';

const pageSchema = JSON.parse(fs.readFileSync('protocol/aml-page.schema.json', 'utf8'));
const receiptSchema = JSON.parse(fs.readFileSync('protocol/aml-dom-receipt.schema.json', 'utf8'));
const evidenceSchema = JSON.parse(fs.readFileSync('protocol/aml-browser-evidence.schema.json', 'utf8'));
const bootstrap = fs.readFileSync('docs/aml.js', 'utf8');
const live = fs.readFileSync('docs/aml-live.js', 'utf8');
const pageManifestRuntime = fs.readFileSync('docs/aml-page-manifest.js', 'utf8');
const browserIntegrity = fs.readFileSync('docs/aml-browser-integrity.js', 'utf8');
const browserEvidence = fs.readFileSync('docs/aml-browser-evidence.js', 'utf8');

test('AML page manifest schema is versioned and bounded', () => {
  assert.equal(pageSchema.properties.schema.const, 'aml-page/1');
  const item = pageSchema.properties.elements.items;
  assert.deepEqual(item.required, ['selector', 'attention_cost', 'restoration_value']);
  assert.equal(item.properties.attention_cost.minimum, 0);
  assert.equal(item.properties.attention_cost.maximum, 10);
  assert.equal(item.properties.restoration_value.minimum, 0);
  assert.equal(item.properties.restoration_value.maximum, 10);
});

test('AML DOM receipt schema exposes inspectable decision totals and optional SHA-256 integrity', () => {
  assert.equal(receiptSchema.properties.schema.const, 'aml-dom-receipt/1');
  assert.ok(receiptSchema.required.includes('totals'));
  assert.ok(receiptSchema.required.includes('decisions'));
  const totals = receiptSchema.properties.totals.required;
  assert.deepEqual(totals, ['evaluated', 'allowed', 'suppressed', 'errors']);
  assert.equal(receiptSchema.properties.integrity.properties.schema.const, 'aml-integrity/1');
  assert.equal(receiptSchema.properties.integrity.properties.algorithm.const, 'SHA-256');
  assert.equal(receiptSchema.properties.integrity.properties.value.pattern, '^[a-f0-9]{64}$');
});

test('AML browser evidence schema binds receipt, violations, and integrity', () => {
  assert.equal(evidenceSchema.properties.schema.const, 'aml-browser-evidence/1');
  assert.ok(evidenceSchema.required.includes('receipt'));
  assert.ok(evidenceSchema.required.includes('zone_violations'));
  assert.ok(evidenceSchema.required.includes('integrity'));
  assert.equal(evidenceSchema.properties.zone_violations.maxItems, 100);
  assert.equal(evidenceSchema.properties.integrity.properties.algorithm.const, 'SHA-256');
});

test('one-script browser bootstrap activates all reference browser layers', () => {
  assert.match(bootstrap, /\.\/aml-gate\.js/);
  assert.match(bootstrap, /\.\/aml-live\.js/);
  assert.match(bootstrap, /\.\/aml-page-manifest\.js/);
  assert.match(bootstrap, /\.\/aml-browser-evidence\.js/);
  assert.match(bootstrap, /browser_integrity: 'SHA-256'/);
  assert.match(bootstrap, /__AML_EVIDENCE__/);
  assert.match(bootstrap, /aml-browser-bootstrap\/1/);
});

test('live DOM firewall publishes bounded receipt history and seals receipts asynchronously', () => {
  assert.match(live, /__AML_RECEIPT_HISTORY__/);
  assert.match(live, /length > 50/);
  assert.match(live, /sealBrowserReceipt/);
  assert.match(live, /aml-receipt-sealed/);
  assert.match(live, /attributeFilter: WATCHED_ATTRIBUTES/);
  assert.doesNotMatch(live, /WATCHED_ATTRIBUTES[\s\S]*data-aml-decision/);
});

test('browser integrity uses canonical sorted JSON and SHA-256 without overstating trust', () => {
  assert.match(browserIntegrity, /Object\.keys\(value\)\.sort\(\)/);
  assert.match(browserIntegrity, /crypto\.subtle\.digest\('SHA-256'/);
  assert.match(browserIntegrity, /AML_BROWSER_RECEIPT_HASH_MISMATCH/);
  assert.match(browserIntegrity, /not a signature/i);
});

test('browser evidence verifies both sealed receipt and complete packet hash', () => {
  assert.match(browserEvidence, /verifyBrowserReceipt/);
  assert.match(browserEvidence, /aml-browser-evidence\/1/);
  assert.match(browserEvidence, /__AML_EVIDENCE_HISTORY__/);
  assert.match(browserEvidence, /AML_BROWSER_EVIDENCE_HASH_MISMATCH/);
  assert.match(browserEvidence, /zone_violations/);
});

test('page manifest runtime fails closed and limits machine-selected DOM scope', () => {
  assert.match(pageManifestRuntime, /MAX_ENTRIES = 100/);
  assert.match(pageManifestRuntime, /MAX_TOTAL_MATCHES = 1000/);
  assert.match(pageManifestRuntime, /AML_PAGE_TOO_MANY_ENTRIES/);
  assert.match(pageManifestRuntime, /AML_PAGE_INVALID_SELECTOR/);
  assert.match(pageManifestRuntime, /AML_PAGE_INVALID_SCORE/);
  assert.match(pageManifestRuntime, /AML_PAGE_MATCH_LIMIT/);
  assert.match(pageManifestRuntime, /AML_PAGE_INVALID_JSON/);
});
