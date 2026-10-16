import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { webcrypto } from 'node:crypto';

if (!globalThis.crypto?.subtle) globalThis.crypto = webcrypto;

import { sealBrowserReceipt, sha256Browser } from '../docs/aml-browser-integrity.js';
import { createBrowserEvidence } from '../docs/aml-browser-evidence.js';
import { createVerificationChallenge } from '../docs/aml-verification-challenge.js';
import { createSessionAttestation } from '../docs/aml-session-attestation.js';
import { createWitnessBundle, verifyWitnessBundle, witnessBundlePayload } from '../docs/aml-witness-bundle.js';
import { witnessVerificationReport } from '../docs/aml-verification-report.js';
import { createVerifierKeyPair, signVerificationReport } from '../docs/aml-signed-verification-report.js';
import { createSignedVerificationQuorum, fingerprintVerifierPublicKey,
  verifySignedVerificationQuorum } from '../docs/aml-signed-verification-quorum.js';

function report(verifier) {
  return {
    schema: 'aml-verification-report/1', prototype: true, verifier,
    artifact_type: 'aml-witness-bundle/1', artifact_hash: 'a'.repeat(64),
    valid: true, reason: 'AML_WITNESS_BUNDLE_VALID',
    checked_at: '2030-01-01T00:05:00.000Z', checks: {}, notes: []
  };
}

test('offline CLI verifies a saved signed quorum and gates on its threshold', async (t) => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'aml-signed-quorum-cli-'));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const write = (name, value) => {
    const file = path.join(directory, name);
    fs.writeFileSync(file, `${JSON.stringify(value)}\n`);
    return file;
  };
  const run = (...args) => spawnSync(process.execPath, ['bin/aml.js', 'verify-signed-quorum', ...args], {
    cwd: process.cwd(), encoding: 'utf8'
  });

  const a = await signVerificationReport(report('a'), await createVerifierKeyPair());
  const b = await signVerificationReport(report('b'), await createVerifierKeyPair());
  const keyPath = write('verifier-key.json', a.verifier_public_key_jwk);
  const fingerprintRun = spawnSync(process.execPath,
    ['bin/aml.js', 'fingerprint-verifier-key', keyPath], { encoding: 'utf8' });
  assert.equal(fingerprintRun.status, 0, fingerprintRun.stderr);
  assert.deepEqual(JSON.parse(fingerprintRun.stdout),
    await fingerprintVerifierPublicKey(a.verifier_public_key_jwk));
  const privateKeyRun = spawnSync(process.execPath, ['bin/aml.js', 'fingerprint-verifier-key',
    write('not-public.json', { ...a.verifier_public_key_jwk, d: 'secret' })], { encoding: 'utf8' });
  assert.equal(privateKeyRun.status, 1);
  assert.match(privateKeyRun.stderr, /AML_SIGNED_QUORUM_PUBLIC_KEY_INVALID/);
  const quorum = await createSignedVerificationQuorum([a, b], { threshold: 2 });
  const valid = run(write('quorum.json', quorum));
  assert.equal(valid.status, 0, valid.stderr);
  assert.equal(JSON.parse(valid.stdout).threshold_met, true);

  const policy = {
    schema: 'aml-signed-quorum-held-policy/1', prototype: true,
    artifact_type: 'aml-witness-bundle/1', artifact_hash: 'a'.repeat(64),
    trusted_key_fingerprints: [a.verifier_key_fingerprint, b.verifier_key_fingerprint],
    threshold: 2
  };
  const policyFile = write('held-policy.json', policy);
  const pinned = run(write('pinned.json', quorum), '--policy', policyFile);
  assert.equal(pinned.status, 0, pinned.stderr);
  assert.equal(JSON.parse(pinned.stdout).policy_met, true);

  // Each ambiguous file would have passed the old last-key-wins JSON.parse
  // path. A nested escaped alias must fail just like a duplicate top-level key.
  for (const [name, source, isPolicy] of [
    ['duplicate-quorum', JSON.stringify(quorum).replace('"prototype":true',
      '"prototype":false,"prototype":true'), false],
    ['escaped-report-key', JSON.stringify(quorum).replace('"valid":true',
      String.raw`"v\u0061lid":false,"valid":true`), false],
    ['duplicate-policy', JSON.stringify(policy).replace('"prototype":true',
      String.raw`"prot\u006ftype":false,"prototype":true`), true]
  ]) {
    assert.deepEqual(JSON.parse(source), isPolicy ? policy : quorum, name);
    const raw = path.join(directory, `${name}.json`);
    fs.writeFileSync(raw, `${source}\n`);
    const args = isPolicy ? [write(`${name}-quorum.json`, quorum), '--policy', raw] : [raw];
    const ambiguous = run(...args);
    assert.equal(ambiguous.status, 1, `${name}: ${ambiguous.stderr}`);
    assert.match(ambiguous.stderr, /duplicate JSON object key/, name);
    assert.equal(ambiguous.stdout, '', name);
  }

  // A lossy UTF-8 decode could turn invalid bytes into the signed U+FFFD
  // character and accept a malformed file as that signed JSON value.
  const replacement = await signVerificationReport(report('\uFFFD'), await createVerifierKeyPair());
  const replacementQuorum = await createSignedVerificationQuorum([replacement], { threshold: 1 });
  const exactBytes = Buffer.from(JSON.stringify(replacementQuorum));
  const marker = Buffer.from('\uFFFD');
  const markerAt = exactBytes.indexOf(marker);
  assert.ok(markerAt >= 0);
  const invalidBytes = Buffer.concat([exactBytes.subarray(0, markerAt), Buffer.from([0xff]),
    exactBytes.subarray(markerAt + marker.length)]);
  assert.deepEqual(JSON.parse(invalidBytes.toString('utf8')), replacementQuorum);
  const invalidUtf8Path = path.join(directory, 'invalid-utf8.json');
  fs.writeFileSync(invalidUtf8Path, invalidBytes);
  const lossy = run(invalidUtf8Path);
  assert.equal(lossy.status, 1, lossy.stderr);
  assert.match(lossy.stderr, /not valid for encoding utf-8/);
  assert.equal(lossy.stdout, '');
  const bomPath = path.join(directory, 'bom.json');
  fs.writeFileSync(bomPath, Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]),
    Buffer.from(JSON.stringify(quorum))]));
  const bom = run(bomPath);
  assert.equal(bom.status, 1, bom.stderr);
  assert.equal(bom.stdout, '');

  const selfSelected = await signVerificationReport(report('self-selected'), await createVerifierKeyPair());
  const otherQuorum = await createSignedVerificationQuorum([a, selfSelected], { threshold: 2 });
  const blocked = run(write('self-selected.json', otherQuorum), '--policy', policyFile);
  assert.equal(blocked.status, 2, blocked.stderr);
  assert.equal(JSON.parse(blocked.stdout).valid, true);
  assert.equal(JSON.parse(blocked.stdout).threshold_met, true);
  assert.equal(JSON.parse(blocked.stdout).policy_met, false);

  const badPolicy = run(write('quorum-for-bad-policy.json', quorum), '--policy',
    write('bad-policy.json', { ...policy, threshold: 3 }));
  assert.equal(badPolicy.status, 1);
  assert.match(badPolicy.stderr, /AML_SIGNED_QUORUM_POLICY_THRESHOLD_INVALID/);

  const inflated = structuredClone(quorum);
  inflated.summary.distinct_keys = 3;
  const rejected = run(write('inflated.json', inflated));
  assert.equal(rejected.status, 2, rejected.stderr);
  assert.equal(JSON.parse(rejected.stdout).reason, 'AML_SIGNED_QUORUM_MISMATCH');

  const unmet = await createSignedVerificationQuorum([a], { threshold: 2 });
  const belowThreshold = run(write('unmet.json', unmet));
  assert.equal(belowThreshold.status, 2, belowThreshold.stderr);
  assert.equal(JSON.parse(belowThreshold.stdout).valid, true);
  assert.equal(JSON.parse(belowThreshold.stdout).threshold_met, false);

  const missing = run();
  assert.equal(missing.status, 1);
  assert.match(missing.stderr, /Usage: aml verify-signed-quorum/);
});

test('signed quorum rechecks the named witness against a separately held challenge', async (t) => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'aml-quorum-witness-'));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const write = (name, value) => {
    const file = path.join(directory, name);
    fs.writeFileSync(file, `${JSON.stringify(value)}\n`);
    return file;
  };
  const run = (...args) => spawnSync(process.execPath, ['bin/aml.js', 'verify-signed-quorum', ...args], {
    cwd: process.cwd(), encoding: 'utf8'
  });

  const receipt = await sealBrowserReceipt({ schema: 'aml-dom-receipt/1', decisions: [] });
  const evidence = await createBrowserEvidence(receipt, { url: 'https://example.test/' });
  const challenge = createVerificationChallenge({ ttl_ms: 120000 });
  const attestation = await createSessionAttestation({ evidence, challenge });
  await new Promise(resolve => setTimeout(resolve, 10));
  const bundle = await createWitnessBundle({ evidence, challenge, attestation });
  assert.ok(Date.parse(bundle.created_at) > Date.parse(attestation.issued_at));
  const check = await verifyWitnessBundle(bundle, { expectedChallenge: challenge });
  assert.equal(check.valid, true);
  const a = await signVerificationReport(witnessVerificationReport(bundle, check, { verifier: 'a' }),
    await createVerifierKeyPair());
  const b = await signVerificationReport(witnessVerificationReport(bundle, check, { verifier: 'b' }),
    await createVerifierKeyPair());
  const quorum = await createSignedVerificationQuorum([a, b], { threshold: 2 });
  const quorumPath = write('quorum.json', quorum);
  const bundlePath = write('bundle.json', bundle);
  const challengePath = write('held-challenge.json', challenge);

  const replayed = await verifySignedVerificationQuorum(quorum, {
    witnessBundle: bundle, expectedChallenge: challenge
  });
  assert.equal(replayed.valid, true);
  assert.equal(replayed.threshold_met, true);
  assert.equal(replayed.witness_met, true);
  assert.equal(replayed.replayable_claims_consistent, true);
  assert.equal(replayed.replayable_claims_evaluation.positive_signed_reports, 2);
  const accepted = run(quorumPath, '--bundle', bundlePath, '--challenge', challengePath);
  assert.equal(accepted.status, 0, accepted.stderr);
  assert.equal(JSON.parse(accepted.stdout).witness_met, true);
  assert.equal(JSON.parse(accepted.stdout).replayable_claims_consistent, true);

  for (const [name, original, other] of [
    ['bundle', bundle, challengePath], ['challenge', challenge, bundlePath]
  ]) {
    const raw = path.join(directory, `duplicate-${name}.json`);
    fs.writeFileSync(raw, `${JSON.stringify(original).replace('"prototype":true',
      String.raw`"prot\u006ftype":false,"prototype":true`)}\n`);
    assert.deepEqual(JSON.parse(fs.readFileSync(raw, 'utf8')), original, name);
    const args = name === 'bundle'
      ? [quorumPath, '--bundle', raw, '--challenge', other]
      : [quorumPath, '--bundle', other, '--challenge', raw];
    const ambiguous = run(...args);
    assert.equal(ambiguous.status, 1, `${name}: ${ambiguous.stderr}`);
    assert.match(ambiguous.stderr, /duplicate JSON object key/, name);
    assert.equal(ambiguous.stdout, '', name);
  }

  const differentChallenge = { ...challenge,
    issued_at: new Date(Date.parse(challenge.issued_at) - 1000).toISOString() };
  const rejected = run(quorumPath, '--bundle', bundlePath, '--challenge',
    write('other-challenge.json', differentChallenge));
  assert.equal(rejected.status, 2, rejected.stderr);
  const rejection = JSON.parse(rejected.stdout);
  assert.equal(rejection.valid, true);
  assert.equal(rejection.threshold_met, true);
  assert.equal(rejection.witness_met, false);
  assert.equal(rejection.replayable_claims_consistent, false);
  assert.equal(rejection.witness_evaluation.reason, 'AML_WITNESS_BUNDLE_CHALLENGE_MISMATCH');

  const tampered = structuredClone(bundle);
  tampered.created_at = '2030-01-01T00:00:00.000Z';
  const damaged = await verifySignedVerificationQuorum(quorum, {
    witnessBundle: tampered, expectedChallenge: challenge
  });
  assert.equal(damaged.valid, true);
  assert.equal(damaged.witness_met, false);
  assert.equal(damaged.witness_evaluation.reason, 'AML_WITNESS_BUNDLE_HASH_MISMATCH');

  const otherBundle = structuredClone(bundle);
  otherBundle.created_at = '2030-01-01T00:00:00.000Z';
  otherBundle.integrity.value = await sha256Browser(witnessBundlePayload(otherBundle));
  const other = await verifySignedVerificationQuorum(quorum, {
    witnessBundle: otherBundle, expectedChallenge: challenge
  });
  assert.equal(other.valid, true);
  assert.equal(other.witness_evaluation.local_bundle_valid, true);
  assert.equal(other.witness_evaluation.artifact_matches, false);
  assert.equal(other.witness_met, false);

  await assert.rejects(
    () => verifySignedVerificationQuorum(quorum, { witnessBundle: bundle }),
    /AML_SIGNED_QUORUM_WITNESS_INPUTS_REQUIRED/
  );
  assert.equal(run(quorumPath, '--bundle', bundlePath).status, 1);

  const invalidSignature = structuredClone(a);
  invalidSignature.report.session_key_fingerprint = '0'.repeat(64);
  const withUnauthenticatedClaim = await createSignedVerificationQuorum(
    [a, b, invalidSignature], { threshold: 2 }
  );
  const ignored = await verifySignedVerificationQuorum(withUnauthenticatedClaim, {
    witnessBundle: bundle, expectedChallenge: challenge
  });
  assert.equal(ignored.replayable_claims_consistent, true);
  assert.equal(ignored.replayable_claims_evaluation.positive_signed_reports, 2);

  // The signatures and held policy can all pass even when a signer asserts a
  // conflicting fact about the session or a step of the reference verifier.
  for (const [field, contradict] of [
    ['session_key_fingerprint', (report) => { report.session_key_fingerprint = '0'.repeat(64); }],
    ['challenge_expires_at', (report) => { report.challenge_expires_at = '2030-01-01T00:00:00.000Z'; }],
    ['checked_at-before-issue', (report) => {
      report.checked_at = new Date(Date.parse(challenge.issued_at) - 1).toISOString();
    }],
    ['checked_at-before-bundle', (report) => { report.checked_at = attestation.issued_at; }],
    ['checked_at-after-expiry', (report) => {
      report.checked_at = new Date(Date.parse(challenge.expires_at) + 1).toISOString();
    }],
    ['checked_at-invalid-calendar-date', (report) => {
      report.checked_at = '2030-02-30T00:00:00.000Z';
    }],
    ['checks.session_signature', (report) => { report.checks.session_signature = false; }],
    ['checks.challenge_binding', (report) => { report.checks.challenge_binding = 'true'; }]
  ]) {
    const falseReport = witnessVerificationReport(bundle, check, { verifier: `contradicts-${field}` });
    contradict(falseReport);
    const signed = await signVerificationReport(falseReport, await createVerifierKeyPair());
    const contradictoryQuorum = await createSignedVerificationQuorum([signed, b], { threshold: 2 });
    const heldPolicy = {
      schema: 'aml-signed-quorum-held-policy/1', prototype: true,
      artifact_type: contradictoryQuorum.artifact_type, artifact_hash: contradictoryQuorum.artifact_hash,
      trusted_key_fingerprints: [signed.verifier_key_fingerprint, b.verifier_key_fingerprint],
      threshold: 2
    };
    const result = await verifySignedVerificationQuorum(contradictoryQuorum, {
      policy: heldPolicy, witnessBundle: bundle, expectedChallenge: challenge
    });
    assert.equal(result.valid, true, field);
    assert.equal(result.threshold_met, true, field);
    assert.equal(result.policy_met, true, field);
    assert.equal(result.witness_met, true, field);
    assert.equal(result.replayable_claims_consistent, false, field);
    assert.deepEqual(result.replayable_claims_evaluation.conflicts,
      [{ report_index: 0, fields: [field.startsWith('checked_at-') ? 'checked_at' : field] }]);
    const fromCli = run(write(`quorum-${field}.json`, contradictoryQuorum),
      '--policy', write(`policy-${field}.json`, heldPolicy),
      '--bundle', bundlePath, '--challenge', challengePath);
    assert.equal(fromCli.status, 2, `${field}: ${fromCli.stderr}`);
    assert.equal(JSON.parse(fromCli.stdout).witness_met, true);
    assert.equal(JSON.parse(fromCli.stdout).replayable_claims_consistent, false);
  }

  // A self-contained signer can truthfully say it did not retain a separate
  // challenge. Replaying with ours cannot retroactively change that claim.
  const selfContained = await verifyWitnessBundle(bundle);
  const independentReport = witnessVerificationReport(bundle, selfContained, { verifier: 'self-contained' });
  independentReport.checks.another_verifier_step = false;
  const independent = await signVerificationReport(independentReport, await createVerifierKeyPair());
  const mixed = await createSignedVerificationQuorum([independent, b], { threshold: 2 });
  assert.equal((await verifySignedVerificationQuorum(mixed, {
    witnessBundle: bundle, expectedChallenge: challenge
  })).replayable_claims_consistent, true);
});
