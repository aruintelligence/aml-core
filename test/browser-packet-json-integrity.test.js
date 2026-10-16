import test from 'node:test';
import assert from 'node:assert/strict';

import { canonicalJSONStringifyBrowser, sealBrowserReceipt, sha256Browser,
  verifyBrowserReceipt } from '../docs/aml-browser-integrity.js';
import { createBrowserEvidence, verifyBrowserEvidence } from '../docs/aml-browser-evidence.js';

function makeReceipt() {
  return { schema: 'aml-dom-receipt/1', decisions: [{ id: 'one' }] };
}

test('browser receipt rejects mutations omitted or changed by JSON serialization', async () => {
  const cases = [
    ['array property', (receipt) => { receipt.decisions.audit_note = 'added'; }, 'AML_CANONICAL_JSON_NON_JSON_ARRAY'],
    ['sparse array slot', (receipt) => { delete receipt.decisions[0]; }, 'AML_CANONICAL_JSON_NON_JSON_ARRAY'],
    ['hidden object field', (receipt) => {
      Object.defineProperty(receipt.decisions[0], 'audit_note', { value: 'added' });
    }, 'AML_CANONICAL_JSON_NON_JSON_OBJECT'],
    ['symbol object field', (receipt) => {
      receipt.decisions[0][Symbol('audit')] = 'added';
    }, 'AML_CANONICAL_JSON_NON_JSON_OBJECT'],
    ['undefined object field', (receipt) => {
      receipt.decisions[0].audit_note = undefined;
    }, 'AML_CANONICAL_JSON_UNSUPPORTED_VALUE'],
    ['accessor object field', (receipt) => {
      Object.defineProperty(receipt.decisions[0], 'id', { get: () => 'one', enumerable: true });
    }, 'AML_CANONICAL_JSON_NON_JSON_OBJECT']
  ];
  for (const [name, mutate, reason] of cases) {
    const receipt = await sealBrowserReceipt(makeReceipt());
    assert.equal((await verifyBrowserReceipt(receipt)).valid, true, name);
    mutate(receipt);
    const result = await verifyBrowserReceipt(receipt);
    assert.equal(result.valid, false, name);
    assert.equal(result.reason, reason, name);
  }
});

test('previously colliding receipt mutations keep the same digest but now fail verification', async () => {
  for (const mutate of [
    (receipt) => { receipt.decisions.audit_note = 'added'; },
    (receipt) => { Object.defineProperty(receipt.decisions[0], 'audit_note', { value: 'added' }); }
  ]) {
    const receipt = await sealBrowserReceipt(makeReceipt());
    const canonical = canonicalJSONStringifyBrowser(receipt);
    const digest = await sha256Browser(receipt);
    mutate(receipt);
    assert.equal(canonicalJSONStringifyBrowser(receipt), canonical);
    assert.equal(await sha256Browser(receipt), digest);
    assert.equal((await verifyBrowserReceipt(receipt)).valid, false);
  }
  const receipt = await sealBrowserReceipt({ schema: 'aml-dom-receipt/1', decisions: [null] });
  const canonical = canonicalJSONStringifyBrowser(receipt);
  delete receipt.decisions[0];
  assert.equal(canonicalJSONStringifyBrowser(receipt), canonical);
  assert.equal((await verifyBrowserReceipt(receipt)).reason, 'AML_CANONICAL_JSON_NON_JSON_ARRAY');
});

test('browser receipt sealing refuses values with no unambiguous JSON representation', async () => {
  const cases = [
    (receipt) => { receipt.decisions.audit_note = 'added'; },
    (receipt) => { receipt.decisions = new Array(1); },
    (receipt) => { receipt.decisions[0].id = undefined; },
    (receipt) => { receipt.decisions[0].id = Infinity; },
    (receipt) => { receipt.decisions[0].self = receipt.decisions[0]; },
    (receipt) => { receipt.decisions[0].id = new Date(); }
  ];
  for (const mutate of cases) {
    const receipt = makeReceipt();
    mutate(receipt);
    await assert.rejects(sealBrowserReceipt(receipt), /AML_CANONICAL_JSON_/);
  }
});

test('browser receipt checks the declared integrity method and exact fields', async () => {
  for (const [mutate, reason] of [
    [(receipt) => { receipt.integrity.canonicalization = 'other-json'; }, 'AML_BROWSER_RECEIPT_CANONICALIZATION_UNSUPPORTED'],
    [(receipt) => { receipt.integrity.algorithm = 'SHA-1'; }, 'AML_BROWSER_RECEIPT_ALGORITHM_UNSUPPORTED'],
    [(receipt) => { receipt.integrity.audit_note = 'extra'; }, 'AML_BROWSER_RECEIPT_INTEGRITY_INVALID'],
    [(receipt) => { receipt.integrity.value = 'not-a-digest'; }, 'AML_BROWSER_RECEIPT_INTEGRITY_INVALID']
  ]) {
    const receipt = await sealBrowserReceipt(makeReceipt());
    mutate(receipt);
    assert.deepEqual((await verifyBrowserReceipt(receipt)).reason, reason);
  }
});

test('browser evidence rejects receipt and packet changes invisible to their hashes', async () => {
  const receipt = await sealBrowserReceipt(makeReceipt());
  const evidence = await createBrowserEvidence(receipt, { url: 'https://example.test/' });
  assert.equal((await verifyBrowserEvidence(evidence)).valid, true);
  evidence.zone_violations.audit_note = 'added';
  assert.equal((await verifyBrowserEvidence(evidence)).reason, 'AML_CANONICAL_JSON_NON_JSON_ARRAY');
  delete evidence.zone_violations.audit_note;
  evidence.integrity.canonicalization = 'other-json';
  assert.equal((await verifyBrowserEvidence(evidence)).reason, 'AML_BROWSER_EVIDENCE_CANONICALIZATION_UNSUPPORTED');
  evidence.integrity.canonicalization = 'sorted-json-v1';
  evidence.integrity.audit_note = 'extra';
  assert.equal((await verifyBrowserEvidence(evidence)).reason, 'AML_BROWSER_EVIDENCE_INTEGRITY_INVALID');
  delete evidence.integrity.audit_note;
  receipt.decisions.audit_note = 'added';
  assert.equal((await verifyBrowserEvidence(evidence)).valid, false);
  await assert.rejects(createBrowserEvidence(receipt), /AML_BROWSER_EVIDENCE_RECEIPT_INVALID/);
});
