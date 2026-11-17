// Release-blocker review: js/user-controlled-bypass at
// docs/aml-signed-verification-quorum.js (witness replay runs only when a
// witness bundle is supplied). Threat model: the submitter controls the saved
// quorum, every signed report from its own keys, the witness bundle and the
// challenge inside it, and may omit any of them. The relying party controls
// its retained challenge, its policy and which options it passes, and accepts
// only on `requested_conditions_met` (CLI exit 0). Synthetic fixtures only.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { sealBrowserReceipt } from '../docs/aml-browser-integrity.js';
import { createBrowserEvidence } from '../docs/aml-browser-evidence.js';
import { createVerificationChallenge } from '../docs/aml-verification-challenge.js';
import { createSessionAttestation } from '../docs/aml-session-attestation.js';
import { createWitnessBundle, verifyWitnessBundle } from '../docs/aml-witness-bundle.js';
import { witnessVerificationReport } from '../docs/aml-verification-report.js';
import { createVerifierKeyPair, signVerificationReport } from '../docs/aml-signed-verification-report.js';
import { createSignedVerificationQuorum, verifySignedVerificationQuorum } from '../docs/aml-signed-verification-quorum.js';

async function attackerQuorum() {
  const receipt = await sealBrowserReceipt({ schema: 'aml-dom-receipt/1', decisions: [] });
  const evidence = await createBrowserEvidence(receipt, { url: 'https://attacker.example.test/' });
  const challenge = createVerificationChallenge({ ttl_ms: 120000 });
  const attestation = await createSessionAttestation({ evidence, challenge });
  await new Promise(resolve => setTimeout(resolve, 5));
  const bundle = await createWitnessBundle({ evidence, challenge, attestation });
  const check = await verifyWitnessBundle(bundle, { expectedChallenge: challenge });
  const reports = [];
  for (const verifier of ['attacker-a', 'attacker-b']) {
    reports.push(await signVerificationReport(witnessVerificationReport(bundle, check, { verifier }),
      await createVerifierKeyPair()));
  }
  return { bundle, quorum: await createSignedVerificationQuorum(reports, { threshold: 2 }) };
}

test('omitting or substituting the witness cannot satisfy a relying party that retained a challenge', async t => {
  const { bundle, quorum } = await attackerQuorum();
  const held = createVerificationChallenge({ ttl_ms: 120000 });
  await assert.rejects(() => verifySignedVerificationQuorum(quorum, { expectedChallenge: held }),
    /AML_SIGNED_QUORUM_WITNESS_INPUTS_REQUIRED/, 'omission is a usage error, not an acceptance');
  const substituted = await verifySignedVerificationQuorum(quorum, { witnessBundle: bundle, expectedChallenge: held });
  assert.equal(substituted.witness_met, false);
  assert.equal(substituted.witness_evaluation.retained_challenge_matched, false);
  assert.equal(substituted.requested_conditions_met, false);
  assert.ok(substituted.requested_conditions.unmet.includes('witness_met'));
  // Preserved counterexample: `valid` describes only the saved quorum's internal
  // consistency and stays true. A caller that reads `valid` alone is misled.
  assert.equal(substituted.valid, true);

  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'aml-quorum-presence-'));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const write = (name, value) => { const file = path.join(directory, name); fs.writeFileSync(file, JSON.stringify(value)); return file; };
  const cli = (...args) => spawnSync(process.execPath, ['bin/aml.js', 'verify-signed-quorum', ...args],
    { cwd: process.cwd(), encoding: 'utf8' });
  const q = write('quorum.json', quorum), b = write('bundle.json', bundle), c = write('held.json', held);
  assert.equal(cli(q, '--challenge', c).status, 1, 'CLI refuses a challenge without a bundle');
  assert.equal(cli(q, '--bundle', b, '--challenge', c).status, 2, 'CLI rejects a substituted witness');
  const own = cli(q, '--bundle', b, '--challenge', write('own.json', bundle.challenge));
  // Requested conditions are met, but without a relying-party-held policy the
  // complete decision is false: exit 3 (consistent, not authorized), never 0.
  assert.equal(own.status, 3, 'the submitter challenge meets the requested conditions only');
  assert.equal(JSON.parse(own.stdout).requested_conditions_met, true);
  assert.equal(JSON.parse(own.stdout).authorized, false);
});

test('without retained inputs the decision states that no witness condition was checked', async () => {
  const { quorum } = await attackerQuorum();
  const result = await verifySignedVerificationQuorum(quorum);
  // Residual, documented: two self-generated keys satisfy key-distinct quorum
  // validity when the relying party supplies no policy or challenge.
  assert.equal(result.requested_conditions_met, true);
  assert.deepEqual(result.requested_conditions.checked, ['valid', 'threshold_met']);
  assert.equal(Object.hasOwn(result, 'witness_met'), false);
  assert.equal(Object.hasOwn(result, 'policy_met'), false);
});
