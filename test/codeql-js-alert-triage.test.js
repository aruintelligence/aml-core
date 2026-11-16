// Directive 010 follow-up: tests behind the triage of the JavaScript
// security-extended alerts. No alert is suppressed; these tests show why an
// alert's condition does not reach permission, or that a test-quality
// weakness is closed by a stronger assertion.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { sealBrowserReceipt } from '../docs/aml-browser-integrity.js';
import { createBrowserEvidence } from '../docs/aml-browser-evidence.js';
import { createVerificationChallenge } from '../docs/aml-verification-challenge.js';
import { createSessionAttestation, resetAMLSessionKey } from '../docs/aml-session-attestation.js';
import { createWitnessBundle, verifyWitnessBundle } from '../docs/aml-witness-bundle.js';

// An attacker-built bundle: the attacker controls every input that the
// js/user-controlled-bypass alerts in aml-session-attestation.js (129, 132,
// 143) and aml-witness-bundle.js (174-192) point at, and makes all of them pass.
async function attackerBundle(url = 'https://attacker.example.test/') {
  resetAMLSessionKey();
  const receipt = await sealBrowserReceipt({ schema: 'aml-dom-receipt/1', prototype: true, revision: 1,
    reason: 'attacker-controlled', url, generated_at: new Date(Date.now() - 1000).toISOString(),
    totals: { evaluated: 0, allowed: 0, suppressed: 0, errors: 0 }, decisions: [] });
  const evidence = await createBrowserEvidence(receipt, { url });
  const challenge = createVerificationChallenge({ ttl_ms: 120000 });
  const attestation = await createSessionAttestation({ evidence, challenge });
  await new Promise(resolve => setTimeout(resolve, 2));
  return { bundle: await createWitnessBundle({ evidence, challenge, attestation }), challenge };
}

test('triage js/user-controlled-bypass: passing every user-controlled guard is consistency, never authorization', async () => {
  const { bundle, challenge } = await attackerBundle();
  const passed = await verifyWitnessBundle(bundle);
  assert.equal(passed.valid, true, 'the attacker can satisfy every flagged guard and the signature check');
  assert.equal(passed.authorized, false);
  assert.deepEqual(passed.authorization.reasons, ['AML_AUTHZ_HELD_CHALLENGE_NOT_MATCHED']);
  // A challenge the verifier did not issue (here: a fresh one) does not help.
  const other = await verifyWitnessBundle(bundle, { expectedChallenge: createVerificationChallenge({ ttl_ms: 60000 }) });
  assert.equal(other.authorized, false);
  // A caller clock never authorizes either.
  const clock = await verifyWitnessBundle(bundle, { expectedChallenge: challenge, now: Date.now() });
  assert.equal(clock.authorized, false);
  // Tampering after the guards (hash mismatch) is not even valid.
  const tampered = structuredClone(bundle);
  tampered.attestation.challenge_nonce = '0'.repeat(tampered.attestation.challenge_nonce.length);
  const bad = await verifyWitnessBundle(tampered, { expectedChallenge: challenge });
  assert.equal(bad.valid, false);
  assert.equal(bad.authorized, false);
});

test('triage js/missing-origin-check: the dedicated worker returns only the decision its own owner could compute', async () => {
  const handlers = [];
  const posted = [];
  const previous = globalThis.self;
  globalThis.self = { addEventListener: (type, fn) => handlers.push([type, fn]), postMessage: m => posted.push(m) };
  try {
    await import(`../docs/aml-verifier-worker.js?triage=${Date.now()}`);
    const [[type, onMessage]] = handlers;
    assert.equal(type, 'message');
    const { bundle, challenge } = await attackerBundle();
    // Any sender (origin is not consulted) without the owner's held challenge: denied.
    await onMessage({ origin: 'https://evil.example', data: { id: 1, bundle } });
    // A sender that holds the challenge gets the same answer it could compute
    // itself by importing aml-witness-bundle.js: the worker grants nothing.
    await onMessage({ origin: 'https://evil.example', data: { id: 2, bundle, expectedChallenge: challenge } });
    await onMessage({ origin: '', data: { id: 3, bundle: { forged: true }, expectedChallenge: challenge } });
    const byId = Object.fromEntries(posted.map(m => [m.id, m]));
    assert.equal(byId[1].authorized, false);
    assert.equal(byId[2].authorized, (await verifyWitnessBundle(bundle, { expectedChallenge: challenge })).authorized);
    assert.equal(byId[3].authorized, false);
    const source = fs.readFileSync(new URL('../docs/aml-verifier-worker.js', import.meta.url), 'utf8');
    assert.doesNotMatch(source, /SharedWorker|onconnect|parent\.postMessage|window\.addEventListener/,
      'dedicated-worker-only assumption behind this triage');
  } finally {
    globalThis.self = previous;
  }
});

test('triage js/bad-tag-filter: the inline-script extraction in tests misses no script element', () => {
  // The flagged regexes extract the page's own inline script for a VM test;
  // they are not sanitizers. Closing the test-quality gap: every <script ...>
  // element, in any case and with any attributes, must be a plain <script>.
  // String scanning only (no HTML regex here, so this test adds no new
  // bad-tag-filter alert of its own).
  const count = (text, needle) => text.split(needle).length - 1;
  for (const page of ['../index.html', '../docs/resilience-lab.html']) {
    const html = fs.readFileSync(new URL(page, import.meta.url), 'utf8');
    const lower = html.toLowerCase();
    const opening = [];
    for (let at = lower.indexOf('<script'); at !== -1; at = lower.indexOf('<script', at + 1)) {
      const next = lower[at + 7];
      if (next === '>' || next === ' ' || next === '\t' || next === '\n' || next === '\r' || next === '/') {
        opening.push(html.slice(at, html.indexOf('>', at) + 1));
      }
    }
    const inline = opening.filter(tag => !tag.toLowerCase().includes('src='));
    assert.ok(inline.length > 0, `${page}: has an inline script`);
    assert.deepEqual(inline.filter(tag => tag !== '<script>'), [],
      `${page}: inline script tags the lower-case extractor would miss`);
    assert.equal(count(html, '</script>'), count(lower, '</script'),
      `${page}: closing tags the extractor would not see`);
  }
});
