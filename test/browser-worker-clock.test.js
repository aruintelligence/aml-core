import test from 'node:test';
import assert from 'node:assert/strict';

import { sealBrowserReceipt } from '../docs/aml-browser-integrity.js';
import { createBrowserEvidence } from '../docs/aml-browser-evidence.js';
import { createVerificationChallenge } from '../docs/aml-verification-challenge.js';
import { createSessionAttestation } from '../docs/aml-session-attestation.js';
import { createWitnessBundle } from '../docs/aml-witness-bundle.js';

test('worker freshness uses its own clock even when the sender supplies now', async () => {
  const receipt = await sealBrowserReceipt({ schema: 'aml-dom-receipt/1', decisions: [] });
  const evidence = await createBrowserEvidence(receipt);
  const challenge = createVerificationChallenge({ ttl_ms: 120000 });
  const attestation = await createSessionAttestation({ evidence, challenge });
  const bundle = await createWitnessBundle({ evidence, challenge, attestation });

  const previousSelf = globalThis.self;
  const previousNow = Date.now;
  let handler;
  const messages = [];
  globalThis.self = {
    addEventListener(type, callback) {
      assert.equal(type, 'message');
      handler = callback;
    },
    postMessage(message) { messages.push(message); }
  };
  try {
    await import('../docs/aml-verifier-worker.js');
    await handler({ data: {
      id: 1, bundle, expectedChallenge: challenge,
      now: Date.parse(challenge.expires_at) + 1
    } });
    assert.equal(messages[0].id, 1);
    assert.equal(messages[0].report.valid, true);
    assert.equal(messages[0].report.checks.verifier_held_challenge, true);

    const expiredNow = Date.parse(challenge.expires_at) + 1;
    Date.now = () => expiredNow;
    await handler({ data: {
      id: 2, bundle, expectedChallenge: challenge,
      now: Date.parse(challenge.issued_at)
    } });
    assert.equal(messages[1].id, 2);
    assert.equal(messages[1].report.valid, false);
    assert.equal(messages[1].report.reason, 'AML_CHALLENGE_EXPIRED');
    assert.equal(messages[1].report.checked_at, new Date(expiredNow).toISOString());
  } finally {
    Date.now = previousNow;
    if (previousSelf === undefined) delete globalThis.self;
    else globalThis.self = previousSelf;
  }
});
