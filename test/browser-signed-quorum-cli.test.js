import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { createHash, webcrypto } from 'node:crypto';

if (!globalThis.crypto?.subtle) globalThis.crypto = webcrypto;

import { canonicalJSONStringifyBrowser, sealBrowserReceipt, sha256Browser } from '../docs/aml-browser-integrity.js';
import { createBrowserEvidence } from '../docs/aml-browser-evidence.js';
import { createVerificationChallenge } from '../docs/aml-verification-challenge.js';
import { createSessionAttestation } from '../docs/aml-session-attestation.js';
import { createWitnessBundle, verifyWitnessBundle, witnessBundlePayload } from '../docs/aml-witness-bundle.js';
import { witnessVerificationReport } from '../docs/aml-verification-report.js';
import { createVerifierKeyPair, signVerificationReport } from '../docs/aml-signed-verification-report.js';
import { createSignedVerificationQuorum, fingerprintVerifierPublicKey,
  verifySignedVerificationQuorum } from '../docs/aml-signed-verification-quorum.js';

const inputHash = value => createHash('sha256')
  .update(canonicalJSONStringifyBrowser(value)).digest('hex');

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
  assert.deepEqual(JSON.parse(valid.stdout).input_fingerprints, {
    canonicalization: 'sorted-json-v1', quorum_sha256: inputHash(quorum)
  });
  const reordered = Object.fromEntries(Object.entries(quorum).reverse());
  assert.equal(JSON.parse(run(write('reordered.json', reordered)).stdout)
    .input_fingerprints.quorum_sha256, inputHash(quorum));

  // The command must finish writing even when its result exceeds pipe buffers
  // on Linux and macOS; an immediate process.exit can truncate valid JSON.
  const verbose = report('verbose');
  verbose.notes = ['x'.repeat(128 * 1024)];
  const largeQuorum = await createSignedVerificationQuorum([
    await signVerificationReport(verbose, await createVerifierKeyPair())
  ], { threshold: 1 });
  const large = run(write('large-quorum.json', largeQuorum));
  assert.equal(large.status, 0, large.stderr);
  assert.ok(large.stdout.length > 128 * 1024);
  assert.equal(JSON.parse(large.stdout).input_fingerprints.quorum_sha256, inputHash(largeQuorum));

  const padded = { ...b, signature: `${b.signature}==` };
  const paddedQuorum = await createSignedVerificationQuorum([a, padded], { threshold: 2 });
  const paddedRun = run(write('padded-signature-quorum.json', paddedQuorum));
  assert.equal(paddedRun.status, 2, paddedRun.stderr);
  assert.equal(JSON.parse(paddedRun.stdout).valid, true);
  assert.equal(JSON.parse(paddedRun.stdout).threshold_met, false);
  assert.deepEqual(JSON.parse(paddedRun.stdout).quorum.summary.disagreement_reasons,
    ['AML_SIGNED_REPORT_SIGNATURE_ENCODING_INVALID']);

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
  assert.deepEqual(JSON.parse(pinned.stdout).input_fingerprints, {
    canonicalization: 'sorted-json-v1', quorum_sha256: inputHash(quorum),
    policy_sha256: inputHash(policy)
  });
  const fingerprint = spawnSync(process.execPath, ['bin/aml.js', 'fingerprint-json', policyFile],
    { encoding: 'utf8' });
  assert.equal(fingerprint.status, 0, fingerprint.stderr);
  assert.deepEqual(JSON.parse(fingerprint.stdout), {
    canonicalization: 'sorted-json-v1', sha256: inputHash(policy)
  });
  const textFingerprint = spawnSync(process.execPath, ['bin/aml.js', 'fingerprint-json',
    write('text.json', 'hello')], { encoding: 'utf8' });
  assert.equal(JSON.parse(textFingerprint.stdout).sha256, inputHash('hello'));
  const duplicateFingerprintPath = path.join(directory, 'duplicate-fingerprint.json');
  fs.writeFileSync(duplicateFingerprintPath, '{"a":1,"\\u0061":2}');
  const ambiguousFingerprint = spawnSync(process.execPath,
    ['bin/aml.js', 'fingerprint-json', duplicateFingerprintPath], { encoding: 'utf8' });
  assert.equal(ambiguousFingerprint.status, 1);
  assert.match(ambiguousFingerprint.stderr, /duplicate JSON object key/);
  const expectedInputs = {
    schema: 'aml-signed-quorum-input-expectations/1', prototype: true,
    canonicalization: 'sorted-json-v1', quorum_sha256: inputHash(quorum),
    policy_sha256: inputHash(policy)
  };
  const expectedFile = write('expected-inputs.json', expectedInputs);
  const bound = run(write('bound-quorum.json', quorum), '--policy', policyFile,
    '--expect-inputs', expectedFile);
  assert.equal(bound.status, 0, bound.stderr);
  assert.equal(JSON.parse(bound.stdout).inputs_met, true);
  assert.deepEqual(JSON.parse(bound.stdout).input_evaluation, {
    expectations_sha256: inputHash(expectedInputs),
    checked: ['quorum_sha256', 'policy_sha256'], mismatched: [], unavailable: []
  });

  // Both the saved threshold and held key policy still pass when their
  // contents change; the separately pinned input digest blocks substitution.
  const swappedQuorum = await createSignedVerificationQuorum([b, a], { threshold: 2 });
  const swapped = run(write('swapped-quorum.json', swappedQuorum), '--policy', policyFile,
    '--expect-inputs', expectedFile);
  assert.equal(swapped.status, 2, swapped.stderr);
  assert.equal(JSON.parse(swapped.stdout).valid, true);
  assert.equal(JSON.parse(swapped.stdout).threshold_met, true);
  assert.equal(JSON.parse(swapped.stdout).policy_met, true);
  assert.equal(JSON.parse(swapped.stdout).inputs_met, false);
  assert.deepEqual(JSON.parse(swapped.stdout).input_evaluation.mismatched, ['quorum_sha256']);
  const reorderedPolicy = { ...policy,
    trusted_key_fingerprints: [...policy.trusted_key_fingerprints].reverse() };
  const changedPolicy = run(write('same-quorum.json', quorum), '--policy',
    write('reordered-policy.json', reorderedPolicy), '--expect-inputs', expectedFile);
  assert.equal(changedPolicy.status, 2, changedPolicy.stderr);
  assert.equal(JSON.parse(changedPolicy.stdout).policy_met, true);
  assert.equal(JSON.parse(changedPolicy.stdout).inputs_met, false);
  assert.deepEqual(JSON.parse(changedPolicy.stdout).input_evaluation.mismatched, ['policy_sha256']);
  const missingPinnedInput = run(write('unpaired-quorum.json', quorum),
    '--expect-inputs', expectedFile);
  assert.equal(missingPinnedInput.status, 1);
  assert.match(missingPinnedInput.stderr, /AML_SIGNED_QUORUM_INPUT_EXPECTATIONS_MISSING_INPUT/);
  const nullInputsPath = path.join(directory, 'null-inputs.json');
  fs.writeFileSync(nullInputsPath, 'null');
  const nullInputs = run(write('null-inputs-quorum.json', quorum),
    '--expect-inputs', nullInputsPath);
  assert.equal(nullInputs.status, 1);
  assert.match(nullInputs.stderr, /AML_SIGNED_QUORUM_INPUT_EXPECTATIONS_INVALID/);
  const nullPolicy = run(write('null-policy-quorum.json', quorum), '--policy', nullInputsPath);
  assert.equal(nullPolicy.status, 1);
  assert.match(nullPolicy.stderr, /AML_SIGNED_QUORUM_POLICY_INVALID/);
  const ambiguousInputsPath = path.join(directory, 'duplicate-inputs.json');
  fs.writeFileSync(ambiguousInputsPath, JSON.stringify(expectedInputs).replace(
    '"prototype":true', String.raw`"prot\u006ftype":false,"prototype":true`));
  const ambiguousInputs = run(write('duplicate-inputs-quorum.json', quorum),
    '--policy', policyFile, '--expect-inputs', ambiguousInputsPath);
  assert.equal(ambiguousInputs.status, 1);
  assert.match(ambiguousInputs.stderr, /duplicate JSON object key/);
  for (const malformed of [
    { ...expectedInputs, policy_sha256: inputHash(policy).toUpperCase() },
    { ...expectedInputs, certified: true },
    { schema: expectedInputs.schema, prototype: true, canonicalization: 'sorted-json-v1' }
  ]) {
    const invalid = run(write('malformed-inputs.json', quorum), '--policy', policyFile,
      '--expect-inputs', write('bad-inputs.json', malformed));
    assert.equal(invalid.status, 1);
    assert.match(invalid.stderr, /AML_SIGNED_QUORUM_INPUT_EXPECTATIONS_INVALID/);
  }

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
  assert.equal(JSON.parse(rejected.stdout).input_fingerprints.quorum_sha256, inputHash(inflated));
  assert.notEqual(inputHash(inflated), inputHash(quorum));

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
  const keyB = await createVerifierKeyPair();
  const a = await signVerificationReport(witnessVerificationReport(bundle, check, { verifier: 'a' }),
    await createVerifierKeyPair());
  const b = await signVerificationReport(witnessVerificationReport(bundle, check, { verifier: 'b' }),
    keyB);
  const quorum = await createSignedVerificationQuorum([a, b], { threshold: 2 });
  const quorumPath = write('quorum.json', quorum);
  const bundlePath = write('bundle.json', bundle);
  const challengePath = write('held-challenge.json', challenge);

  const replayStarted = Date.now();
  const replayed = await verifySignedVerificationQuorum(quorum, {
    witnessBundle: bundle, expectedChallenge: challenge
  });
  assert.equal(replayed.witness_evaluation.clock_source, 'local_system');
  assert.ok(Date.parse(replayed.witness_evaluation.evaluated_at) >= replayStarted);
  assert.ok(Date.parse(replayed.witness_evaluation.evaluated_at) <= Date.now());
  assert.equal(new Date(Date.parse(replayed.witness_evaluation.evaluated_at)).toISOString(),
    replayed.witness_evaluation.evaluated_at);
  assert.equal(replayed.valid, true);
  assert.equal(replayed.threshold_met, true);
  assert.equal(replayed.witness_met, true);
  assert.equal(replayed.replayable_claims_consistent, true);
  assert.equal(replayed.replayable_claims_evaluation.positive_signed_reports, 2);
  assert.deepEqual(replayed.input_fingerprints, {
    canonicalization: 'sorted-json-v1', quorum_sha256: inputHash(quorum),
    witness_bundle_sha256: inputHash(bundle), held_challenge_sha256: inputHash(challenge)
  });
  const accepted = run(quorumPath, '--bundle', bundlePath, '--challenge', challengePath);
  assert.equal(accepted.status, 0, accepted.stderr);
  assert.equal(JSON.parse(accepted.stdout).witness_met, true);
  assert.equal(JSON.parse(accepted.stdout).replayable_claims_consistent, true);
  assert.equal(JSON.parse(accepted.stdout).witness_evaluation.clock_source, 'local_system');
  assert.ok(Date.parse(JSON.parse(accepted.stdout).witness_evaluation.evaluated_at) >= replayStarted);
  assert.ok(Date.parse(JSON.parse(accepted.stdout).witness_evaluation.evaluated_at) <= Date.now());
  assert.deepEqual(JSON.parse(accepted.stdout).input_fingerprints, replayed.input_fingerprints);

  // Prove the printed instant is the same single instant used for freshness.
  const originalNow = Date.now;
  const afterExpiry = Date.parse(challenge.expires_at) + 1;
  let clockReads = 0;
  Date.now = () => { clockReads += 1; return afterExpiry; };
  try {
    const expired = await verifySignedVerificationQuorum(quorum, {
      witnessBundle: bundle, expectedChallenge: challenge
    });
    assert.equal(clockReads, 1);
    assert.equal(expired.valid, true);
    assert.equal(expired.threshold_met, true);
    assert.equal(expired.witness_met, false);
    assert.equal(expired.witness_evaluation.reason, 'AML_CHALLENGE_EXPIRED');
    assert.equal(expired.witness_evaluation.evaluated_at, new Date(afterExpiry).toISOString());
    assert.equal(expired.witness_evaluation.clock_source, 'local_system');
  } finally {
    Date.now = originalNow;
  }

  const completePolicy = {
    schema: 'aml-signed-quorum-held-policy/4', prototype: true,
    artifact_type: quorum.artifact_type, artifact_hash: quorum.artifact_hash,
    trusted_keys: [
      { ...await fingerprintVerifierPublicKey(a.verifier_public_key_jwk), trust_group: 'lab-a' },
      { ...await fingerprintVerifierPublicKey(b.verifier_public_key_jwk), trust_group: 'lab-b' }
    ],
    threshold: 2, group_threshold: 2, require_complete_witness_claims: true
  };
  const completePolicyPath = write('complete-policy.json', completePolicy);
  const complete = run(quorumPath, '--policy', completePolicyPath,
    '--bundle', bundlePath, '--challenge', challengePath);
  assert.equal(complete.status, 0, complete.stderr);
  assert.equal(JSON.parse(complete.stdout).policy_met, true);
  assert.deepEqual(JSON.parse(complete.stdout).policy_evaluation.unsatisfied_claims, []);
  assert.deepEqual(JSON.parse(complete.stdout).input_fingerprints, {
    ...replayed.input_fingerprints, policy_sha256: inputHash(completePolicy)
  });
  const heldInputs = {
    schema: 'aml-signed-quorum-input-expectations/1', prototype: true,
    canonicalization: 'sorted-json-v1', policy_sha256: inputHash(completePolicy),
    held_challenge_sha256: inputHash(challenge)
  };
  const heldInputsPath = write('held-inputs.json', heldInputs);
  const pinnedReplay = run(quorumPath, '--policy', completePolicyPath,
    '--bundle', bundlePath, '--challenge', challengePath, '--expect-inputs', heldInputsPath);
  assert.equal(pinnedReplay.status, 0, pinnedReplay.stderr);
  assert.equal(JSON.parse(pinnedReplay.stdout).inputs_met, true);

  const vetoPolicy = { ...completePolicy, schema: 'aml-signed-quorum-held-policy/5',
    reject_trusted_dissent: true };
  const vetoPath = write('veto-policy.json', vetoPolicy);
  const cleanVeto = run(quorumPath, '--policy', vetoPath,
    '--bundle', bundlePath, '--challenge', challengePath);
  assert.equal(cleanVeto.status, 0, cleanVeto.stderr);
  assert.deepEqual(JSON.parse(cleanVeto.stdout).policy_evaluation.trusted_dissent, []);
  assert.equal(JSON.parse(cleanVeto.stdout).input_fingerprints.policy_sha256, inputHash(vetoPolicy));
  assert.notEqual(inputHash(vetoPolicy), inputHash(completePolicy));

  const negative = witnessVerificationReport(bundle, check, { verifier: 'b-dissent' });
  negative.valid = false;
  negative.reason = 'AML_TEST_SIGNED_DISSENT';
  const dissent = await signVerificationReport(negative, keyB);
  const withDissent = await createSignedVerificationQuorum([a, b, dissent], { threshold: 2 });
  const olderPolicy = await verifySignedVerificationQuorum(withDissent, {
    policy: completePolicy, witnessBundle: bundle, expectedChallenge: challenge
  });
  assert.equal(olderPolicy.policy_met, true);
  const vetoed = await verifySignedVerificationQuorum(withDissent, {
    policy: vetoPolicy, witnessBundle: bundle, expectedChallenge: challenge
  });
  assert.equal(vetoed.valid, true);
  assert.equal(vetoed.threshold_met, true);
  assert.equal(vetoed.witness_met, true);
  assert.equal(vetoed.replayable_claims_consistent, true);
  assert.equal(vetoed.policy_met, false);
  assert.deepEqual(vetoed.policy_evaluation.trusted_dissent,
    [{ report_index: 2, key_material_fingerprint: vetoPolicy.trusted_keys[1].key_material_fingerprint }]);
  const vetoRun = run(write('dissent-quorum.json', withDissent), '--policy', vetoPath,
    '--bundle', bundlePath, '--challenge', challengePath);
  assert.equal(vetoRun.status, 2, vetoRun.stderr);
  assert.equal(JSON.parse(vetoRun.stdout).policy_met, false);

  const alias = structuredClone(dissent);
  alias.verifier_public_key_jwk.kid = 'alternate-metadata-for-same-key';
  alias.verifier_key_fingerprint = await sha256Browser(alias.verifier_public_key_jwk);
  const aliasQuorum = await createSignedVerificationQuorum([a, b, alias], { threshold: 2 });
  const aliasResult = await verifySignedVerificationQuorum(aliasQuorum, {
    policy: vetoPolicy, witnessBundle: bundle, expectedChallenge: challenge
  });
  assert.notEqual(alias.verifier_key_fingerprint, b.verifier_key_fingerprint);
  assert.equal(aliasResult.policy_met, false);
  assert.deepEqual(aliasResult.policy_evaluation.trusted_dissent,
    [{ report_index: 2, key_material_fingerprint: vetoPolicy.trusted_keys[1].key_material_fingerprint }]);

  for (const ignoredDissent of [
    await signVerificationReport(negative, await createVerifierKeyPair()),
    { ...dissent, report: { ...negative, reason: 'changed-without-resigning' } }
  ]) {
    const ignoredQuorum = await createSignedVerificationQuorum([a, b, ignoredDissent], { threshold: 2 });
    const result = await verifySignedVerificationQuorum(ignoredQuorum, {
      policy: vetoPolicy, witnessBundle: bundle, expectedChallenge: challenge
    });
    assert.equal(result.policy_met, true);
    assert.deepEqual(result.policy_evaluation.trusted_dissent, []);
  }
  const missingVetoWitness = run(quorumPath, '--policy', vetoPath);
  assert.equal(missingVetoWitness.status, 1);
  assert.match(missingVetoWitness.stderr, /AML_SIGNED_QUORUM_POLICY_WITNESS_REQUIRED/);
  const malformedVeto = run(quorumPath, '--policy',
    write('malformed-veto.json', { ...vetoPolicy, reject_trusted_dissent: false }),
    '--bundle', bundlePath, '--challenge', challengePath);
  assert.equal(malformedVeto.status, 1);
  assert.match(malformedVeto.stderr, /AML_SIGNED_QUORUM_POLICY_INVALID/);

  for (const [name, change, fields] of [
    ['no-checks', report => { report.checks = {}; }, [
      'checks.bundle_integrity', 'checks.receipt_integrity', 'checks.evidence_integrity',
      'checks.challenge_freshness', 'checks.challenge_binding', 'checks.session_signature',
      'checks.verifier_held_challenge'
    ]],
    ['no-checked-at', report => { delete report.checked_at; }, ['checked_at']],
    ['no-session-key', report => { report.session_key_fingerprint = null; },
      ['session_key_fingerprint']],
    ['no-expiry', report => { delete report.challenge_expires_at; },
      ['challenge_expires_at']],
    ['process-not-asserted', report => { report.checks.verifier_held_challenge = false; },
      ['checks.verifier_held_challenge']]
  ]) {
    const sparse = witnessVerificationReport(bundle, check, { verifier: `sparse-${name}` });
    change(sparse);
    const signedSparse = await signVerificationReport(sparse, await createVerifierKeyPair());
    const sparseQuorum = await createSignedVerificationQuorum([signedSparse, b], { threshold: 2 });
    const sparsePolicy = { ...completePolicy, trusted_keys: [
      { ...await fingerprintVerifierPublicKey(signedSparse.verifier_public_key_jwk),
        trust_group: 'lab-a' }, completePolicy.trusted_keys[1]
    ] };
    const result = await verifySignedVerificationQuorum(sparseQuorum, {
      policy: sparsePolicy, witnessBundle: bundle, expectedChallenge: challenge
    });
    assert.equal(result.valid, true, name);
    assert.equal(result.threshold_met, true, name);
    assert.equal(result.witness_met, true, name);
    assert.equal(result.replayable_claims_consistent, true, name);
    assert.equal(result.policy_met, false, name);
    assert.deepEqual(result.policy_evaluation.unsatisfied_claims,
      [{ report_index: 0, fields }], name);
    const fromCli = run(write(`sparse-${name}.json`, sparseQuorum), '--policy',
      write(`sparse-${name}-policy.json`, sparsePolicy),
      '--bundle', bundlePath, '--challenge', challengePath);
    assert.equal(fromCli.status, 2, `${name}: ${fromCli.stderr}`);
  }

  const missingReplay = run(quorumPath, '--policy', completePolicyPath);
  assert.equal(missingReplay.status, 1);
  assert.match(missingReplay.stderr, /AML_SIGNED_QUORUM_POLICY_WITNESS_REQUIRED/);
  const malformedCompletePolicy = run(quorumPath, '--policy',
    write('invalid-complete-policy.json', { ...completePolicy, require_complete_witness_claims: false }),
    '--bundle', bundlePath, '--challenge', challengePath);
  assert.equal(malformedCompletePolicy.status, 1);
  assert.match(malformedCompletePolicy.stderr, /AML_SIGNED_QUORUM_POLICY_INVALID/);

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
  assert.equal(rejection.input_fingerprints.quorum_sha256, inputHash(quorum));
  assert.equal(rejection.input_fingerprints.held_challenge_sha256, inputHash(differentChallenge));
  assert.notEqual(rejection.input_fingerprints.held_challenge_sha256,
    replayed.input_fingerprints.held_challenge_sha256);
  const pinnedWrongChallenge = run(quorumPath, '--policy', completePolicyPath,
    '--bundle', bundlePath, '--challenge', write('pinned-other-challenge.json', differentChallenge),
    '--expect-inputs', heldInputsPath);
  assert.equal(pinnedWrongChallenge.status, 2, pinnedWrongChallenge.stderr);
  assert.equal(JSON.parse(pinnedWrongChallenge.stdout).valid, true);
  assert.equal(JSON.parse(pinnedWrongChallenge.stdout).inputs_met, false);
  assert.deepEqual(JSON.parse(pinnedWrongChallenge.stdout).input_evaluation.mismatched,
    ['held_challenge_sha256']);

  const tampered = structuredClone(bundle);
  tampered.created_at = '2030-01-01T00:00:00.000Z';
  const damaged = await verifySignedVerificationQuorum(quorum, {
    witnessBundle: tampered, expectedChallenge: challenge
  });
  assert.equal(damaged.valid, true);
  assert.equal(damaged.witness_met, false);
  assert.equal(damaged.witness_evaluation.reason, 'AML_WITNESS_BUNDLE_HASH_MISMATCH');
  assert.equal(damaged.input_fingerprints.witness_bundle_sha256, inputHash(tampered));
  assert.notEqual(damaged.input_fingerprints.witness_bundle_sha256,
    replayed.input_fingerprints.witness_bundle_sha256);

  const hiddenBundle = structuredClone(bundle);
  Object.defineProperty(hiddenBundle, 'unbound', { value: 'hidden' });
  const nonJSON = await verifySignedVerificationQuorum(quorum, {
    witnessBundle: hiddenBundle, expectedChallenge: challenge
  });
  assert.equal(nonJSON.valid, true);
  assert.equal(nonJSON.threshold_met, true);
  assert.equal(nonJSON.witness_met, false);
  assert.equal(Object.hasOwn(nonJSON, 'input_fingerprints'), false);

  const otherBundle = structuredClone(bundle);
  otherBundle.created_at = new Date(Date.parse(bundle.created_at) + 1).toISOString();
  otherBundle.integrity.value = await sha256Browser(witnessBundlePayload(otherBundle));
  const other = await verifySignedVerificationQuorum(quorum, {
    witnessBundle: otherBundle, expectedChallenge: challenge
  });
  assert.equal(other.valid, true);
  assert.equal(other.witness_evaluation.local_bundle_valid, true);
  assert.equal(other.witness_evaluation.artifact_matches, false);
  assert.equal(other.witness_met, false);

  // A producer can reseal a future creation time and sign reports over its
  // new hash. Internal quorum and held policy still pass; replay must refuse
  // the impossible witness timeline as a separate condition.
  const futureBundle = structuredClone(bundle);
  futureBundle.created_at = new Date(Date.now() + 30000).toISOString();
  futureBundle.integrity.value = await sha256Browser(witnessBundlePayload(futureBundle));
  const futureA = await signVerificationReport(
    witnessVerificationReport(futureBundle, check, { verifier: 'future-a' }),
    await createVerifierKeyPair());
  const futureB = await signVerificationReport(
    witnessVerificationReport(futureBundle, check, { verifier: 'future-b' }),
    await createVerifierKeyPair());
  const futureQuorum = await createSignedVerificationQuorum([futureA, futureB], { threshold: 2 });
  const futurePolicy = {
    schema: 'aml-signed-quorum-held-policy/1', prototype: true,
    artifact_type: futureQuorum.artifact_type, artifact_hash: futureQuorum.artifact_hash,
    trusted_key_fingerprints: [futureA.verifier_key_fingerprint, futureB.verifier_key_fingerprint],
    threshold: 2
  };
  const futureResult = await verifySignedVerificationQuorum(futureQuorum, {
    policy: futurePolicy, witnessBundle: futureBundle, expectedChallenge: challenge
  });
  assert.equal(futureResult.valid, true);
  assert.equal(futureResult.threshold_met, true);
  assert.equal(futureResult.policy_met, true);
  assert.equal(futureResult.witness_evaluation.artifact_matches, true);
  assert.equal(futureResult.witness_evaluation.reason, 'AML_WITNESS_BUNDLE_NOT_YET_CREATED');
  assert.equal(futureResult.witness_met, false);
  const futureCli = run(write('future-quorum.json', futureQuorum),
    '--policy', write('future-policy.json', futurePolicy),
    '--bundle', write('future-bundle.json', futureBundle), '--challenge', challengePath);
  assert.equal(futureCli.status, 2, futureCli.stderr);
  assert.equal(JSON.parse(futureCli.stdout).witness_evaluation.reason,
    'AML_WITNESS_BUNDLE_NOT_YET_CREATED');

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
    ['checked_at-after-replay', (report) => {
      report.checked_at = new Date(Date.now() + 30000).toISOString();
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
