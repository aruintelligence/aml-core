// Black-box comparison of saved JS quorums against the project-authored Python verifier.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { webcrypto } from 'node:crypto';
import { sealBrowserReceipt, sha256Browser } from '../docs/aml-browser-integrity.js';
import { createBrowserEvidence } from '../docs/aml-browser-evidence.js';
import { createVerificationChallenge } from '../docs/aml-verification-challenge.js';
import { createSessionAttestation } from '../docs/aml-session-attestation.js';
import { createWitnessBundle, verifyWitnessBundle, witnessBundlePayload } from '../docs/aml-witness-bundle.js';
import { witnessVerificationReport } from '../docs/aml-verification-report.js';
import { createVerifierKeyPair, signVerificationReport } from '../docs/aml-signed-verification-report.js';
import { createSignedVerificationQuorum, fingerprintVerifierPublicKey,
  validateSignedVerificationQuorumPolicy, verifySignedVerificationQuorum
} from '../docs/aml-signed-verification-quorum.js';

if (!globalThis.crypto?.subtle) globalThis.crypto = webcrypto;
const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'aml-python-signed-quorum-'));
const python = path.resolve('independent/python/verify_signed_quorum.py');
const checks = [];
const save = (name, value) => {
  const file = path.join(directory, name);
  fs.writeFileSync(file, typeof value === 'string' ? value : JSON.stringify(value));
  return file;
};
const report = (verifier, valid = true) => ({
  schema: 'aml-verification-report/1', prototype: true, verifier,
  artifact_type: 'aml-witness-bundle/1', artifact_hash: 'a'.repeat(64),
  valid, reason: valid ? 'AML_WITNESS_BUNDLE_VALID' : 'AML_SESSION_SIGNATURE_INVALID',
  checked_at: '2030-01-01T00:05:00.000Z', checks: { bundle_integrity: valid }, notes: []
});

async function compare(name, quorum, policy, expected, { bundle, challenge } = {}) {
  const args = [python, save(`${name}-quorum.json`, quorum)];
  if (policy) args.push('--policy', save(`${name}-policy.json`, policy));
  if (bundle && challenge) args.push('--bundle', save(`${name}-bundle.json`, bundle),
    '--challenge', save(`${name}-challenge.json`, challenge));
  const run = spawnSync('python3', args, {
    encoding: 'utf8', env: { ...process.env, PYTHONDONTWRITEBYTECODE: '1' }
  });
  if (run.error) throw run.error;
  assert.ok(run.stdout, `${name}: ${run.stderr}`);
  const py = JSON.parse(run.stdout);
  const js = await verifySignedVerificationQuorum(quorum, {
    policy, ...(bundle ? { witnessBundle: bundle, expectedChallenge: challenge } : {})
  });
  for (const field of ['valid', 'threshold_met', ...(policy ? ['policy_met'] : []),
    ...(bundle ? ['witness_met', 'replayable_claims_consistent'] : [])]) {
    assert.equal(py[field], js[field], `${name}: ${field}: ${run.stderr} ${run.stdout}`);
  }
  if (bundle) {
    assert.equal(py.witness_evaluation.local_bundle_valid, js.witness_evaluation.local_bundle_valid, name);
    assert.equal(py.witness_evaluation.artifact_matches, js.witness_evaluation.artifact_matches, name);
    assert.deepEqual(py.replayable_claims_evaluation, js.replayable_claims_evaluation, name);
  }
  if (policy && js.valid) assert.deepEqual(py.policy_evaluation, js.policy_evaluation, name);
  assert.equal(py.valid && py.threshold_met && (!policy || py.policy_met) &&
    (!bundle || (py.witness_met && py.replayable_claims_consistent)), expected, name);
  assert.equal(run.status, expected ? 0 : 2, `${name}: ${run.stderr} ${run.stdout}`);
  if (js.valid) assert.deepEqual(py.summary, js.quorum.summary, name);
  checks.push({ case: name, valid: py.valid, threshold_met: py.threshold_met,
    ...(policy ? { policy_met: py.policy_met } : {}),
    ...(bundle ? { witness_met: py.witness_met,
      replayable_claims_consistent: py.replayable_claims_consistent } : {}),
    python_matches_js: true });
}

try {
  const fixedQuorum = JSON.parse(fs.readFileSync('independent/python/signed-quorum-vector.json', 'utf8'));
  const fixedPolicy = JSON.parse(fs.readFileSync(
    'independent/python/signed-quorum-held-policy-vector.json', 'utf8'
  ));
  await compare('published-synthetic-vector', fixedQuorum, fixedPolicy, true);
  const fixedGroupPolicy = JSON.parse(fs.readFileSync(
    'independent/python/signed-quorum-held-group-policy-vector.json', 'utf8'
  ));
  await compare('published-synthetic-group-vector', fixedQuorum, fixedGroupPolicy, true);
  const fixedMaterialPolicy = JSON.parse(fs.readFileSync(
    'independent/python/signed-quorum-held-material-policy-vector.json', 'utf8'
  ));
  await compare('published-synthetic-material-vector', fixedQuorum, fixedMaterialPolicy, true);
  const keyA = await createVerifierKeyPair();
  const keyB = await createVerifierKeyPair();
  const a = await signVerificationReport(report('a'), keyA);
  const b = await signVerificationReport(report('b'), keyB);
  const policy = {
    schema: 'aml-signed-quorum-held-policy/1', prototype: true,
    artifact_type: 'aml-witness-bundle/1', artifact_hash: 'a'.repeat(64),
    trusted_key_fingerprints: [a.verifier_key_fingerprint, b.verifier_key_fingerprint],
    threshold: 2
  };
  const quorum = await createSignedVerificationQuorum([a, b], { threshold: 2 });
  await compare('two-distinct-keys', quorum, policy, true);
  const keyC = await createVerifierKeyPair();
  const c = await signVerificationReport(report('c'), keyC);
  const groupedPolicy = {
    schema: 'aml-signed-quorum-held-policy/2', prototype: true,
    artifact_type: policy.artifact_type, artifact_hash: policy.artifact_hash,
    trusted_keys: [
      { verifier_key_fingerprint: a.verifier_key_fingerprint, trust_group: 'lab-a' },
      { verifier_key_fingerprint: b.verifier_key_fingerprint, trust_group: 'lab-b' }
    ],
    threshold: 2, group_threshold: 2
  };
  await compare('two-buyer-held-trust-groups', quorum, groupedPolicy, true);
  const materialPolicy = { ...groupedPolicy, schema: 'aml-signed-quorum-held-policy/3',
    trusted_keys: [
      { ...await fingerprintVerifierPublicKey(a.verifier_public_key_jwk), trust_group: 'lab-a' },
      { ...await fingerprintVerifierPublicKey(b.verifier_public_key_jwk), trust_group: 'lab-b' }
    ]
  };
  await compare('two-material-pinned-trust-groups', quorum, materialPolicy, true);
  await compare('wrong-held-material-pin', quorum, { ...materialPolicy, trusted_keys: [
    materialPolicy.trusted_keys[0],
    { ...materialPolicy.trusted_keys[1], key_material_fingerprint: '0'.repeat(64) }
  ] }, false);
  await compare('wrong-extra-pin-despite-sufficient-trusted-groups',
    await createSignedVerificationQuorum([a, b, c], { threshold: 2 }),
    { ...materialPolicy, trusted_keys: [...materialPolicy.trusted_keys,
      { ...await fingerprintVerifierPublicKey(c.verifier_public_key_jwk),
        key_material_fingerprint: '0'.repeat(64), trust_group: 'lab-c' }]
    }, false);
  await compare('grouped-policy-met-but-saved-threshold-unmet',
    await createSignedVerificationQuorum([a, b], { threshold: 3 }), groupedPolicy, false);
  await compare('two-keys-one-buyer-held-group', quorum, { ...groupedPolicy, trusted_keys: [
    groupedPolicy.trusted_keys[0],
    { verifier_key_fingerprint: b.verifier_key_fingerprint, trust_group: 'lab-a' },
    { verifier_key_fingerprint: c.verifier_key_fingerprint, trust_group: 'lab-b' }
  ] }, false);
  await compare('missing-key-in-group-policy', quorum, { ...groupedPolicy, trusted_keys: [
    groupedPolicy.trusted_keys[0],
    { verifier_key_fingerprint: c.verifier_key_fingerprint, trust_group: 'lab-b' }
  ] }, false);
  await compare('without-held-policy', quorum, undefined, true);
  await compare('wrong-held-artifact', quorum, { ...policy, artifact_hash: 'b'.repeat(64) }, false);
  await compare('untrusted-key', quorum, { ...policy,
    trusted_key_fingerprints: [a.verifier_key_fingerprint, '0'.repeat(64)] }, false);
  await compare('threshold-unmet',
    await createSignedVerificationQuorum([a, b], { threshold: 3 }), policy, false);
  const inflated = structuredClone(quorum);
  inflated.summary.distinct_keys += 1;
  await compare('inflated-summary', inflated, policy, false);
  const rewritten = structuredClone(quorum);
  rewritten.claim_boundary = 'Certified by external authorities';
  await compare('rewritten-claim-boundary', rewritten, policy, false);
  const altered = structuredClone(quorum);
  altered.signed_reports[0].report.reason = 'altered after signing';
  await compare('report-mutation', altered, policy, false);

  const alias = structuredClone(a);
  alias.verifier_public_key_jwk.kid = 'same-key-new-label';
  alias.verifier_key_fingerprint = await sha256Browser(alias.verifier_public_key_jwk);
  assert.notEqual(alias.verifier_key_fingerprint, a.verifier_key_fingerprint);
  const aliasQuorum = await createSignedVerificationQuorum([a, alias], { threshold: 2 });
  await compare('key-metadata-alias', aliasQuorum, {
    ...policy, trusted_key_fingerprints: [a.verifier_key_fingerprint, alias.verifier_key_fingerprint]
  }, false);
  await compare('key-alias-assigned-to-two-trust-groups',
    await createSignedVerificationQuorum([a, alias, b], { threshold: 2 }),
    { ...groupedPolicy, trusted_keys: [
      groupedPolicy.trusted_keys[0],
      { verifier_key_fingerprint: alias.verifier_key_fingerprint, trust_group: 'lab-b' },
      { verifier_key_fingerprint: b.verifier_key_fingerprint, trust_group: 'lab-a' }
    ] }, false);
  const aliasMaterial = await fingerprintVerifierPublicKey(alias.verifier_public_key_jwk);
  const dormantAliasPolicy = { ...materialPolicy, trusted_keys: [
    materialPolicy.trusted_keys[0], { ...aliasMaterial, trust_group: 'lab-b' }
  ] };
  assert.throws(() => validateSignedVerificationQuorumPolicy(dormantAliasPolicy),
    /AML_SIGNED_QUORUM_POLICY_MATERIAL_INVALID/);
  const dormantAliasUsage = spawnSync('python3', [python, save('dormant-alias-quorum.json', quorum),
    '--policy', save('dormant-alias-policy.json', dormantAliasPolicy)],
  { encoding: 'utf8', env: { ...process.env, PYTHONDONTWRITEBYTECODE: '1' } });
  assert.equal(dormantAliasUsage.status, 1, dormantAliasUsage.stderr);
  assert.equal(JSON.parse(dormantAliasUsage.stdout).reason, 'AML_SIGNED_QUORUM_POLICY_MATERIAL_INVALID');
  const dissent = await signVerificationReport(report('dissent', false), keyB);
  await compare('authenticated-dissent',
    await createSignedVerificationQuorum([a, dissent], { threshold: 2 }), policy, false);
  const invalidSignature = structuredClone(b);
  invalidSignature.signature = `${invalidSignature.signature[0] === 'A' ? 'B' : 'A'}${invalidSignature.signature.slice(1)}`;
  await compare('invalid-signature-counted-as-rejection',
    await createSignedVerificationQuorum([a, invalidSignature], { threshold: 2 }), policy, false);

  const receipt = await sealBrowserReceipt({ schema: 'aml-dom-receipt/1', decisions: [] });
  const evidence = await createBrowserEvidence(receipt, { url: 'https://example.test/' });
  const challenge = createVerificationChallenge({ ttl_ms: 120000 });
  const attestation = await createSessionAttestation({ evidence, challenge });
  await new Promise(resolve => setTimeout(resolve, 10));
  const bundle = await createWitnessBundle({ evidence, challenge, attestation });
  assert.ok(Date.parse(bundle.created_at) > Date.parse(attestation.issued_at));
  const witness = await verifyWitnessBundle(bundle, { expectedChallenge: challenge });
  assert.equal(witness.valid, true);
  const witnessKeyA = await createVerifierKeyPair();
  const witnessKeyB = await createVerifierKeyPair();
  const witnessA = await signVerificationReport(
    witnessVerificationReport(bundle, witness, { verifier: 'witness-a' }), witnessKeyA);
  const witnessB = await signVerificationReport(
    witnessVerificationReport(bundle, witness, { verifier: 'witness-b' }), witnessKeyB);
  const witnessQuorum = await createSignedVerificationQuorum([witnessA, witnessB], { threshold: 2 });
  const witnessPolicy = {
    ...policy, artifact_hash: bundle.integrity.value,
    trusted_key_fingerprints: [witnessA.verifier_key_fingerprint, witnessB.verifier_key_fingerprint]
  };
  const replay = { bundle, challenge };
  await compare('replayed-signed-witness', witnessQuorum, witnessPolicy, true, replay);
  const witnessGroupPolicy = {
    ...groupedPolicy, artifact_hash: bundle.integrity.value,
    trusted_keys: [
      { verifier_key_fingerprint: witnessA.verifier_key_fingerprint, trust_group: 'lab-a' },
      { verifier_key_fingerprint: witnessB.verifier_key_fingerprint, trust_group: 'lab-b' }
    ]
  };
  await compare('replayed-witness-with-two-held-groups',
    witnessQuorum, witnessGroupPolicy, true, replay);
  await compare('replayed-witness-with-material-pins', witnessQuorum,
    { ...witnessGroupPolicy, schema: 'aml-signed-quorum-held-policy/3', trusted_keys: [
      { ...await fingerprintVerifierPublicKey(witnessA.verifier_public_key_jwk), trust_group: 'lab-a' },
      { ...await fingerprintVerifierPublicKey(witnessB.verifier_public_key_jwk), trust_group: 'lab-b' }
    ] }, true, replay);
  await compare('replayed-witness-with-only-one-held-group', witnessQuorum,
    { ...witnessGroupPolicy, trusted_keys: [
      witnessGroupPolicy.trusted_keys[0],
      { verifier_key_fingerprint: witnessB.verifier_key_fingerprint, trust_group: 'lab-a' },
      { verifier_key_fingerprint: '0'.repeat(64), trust_group: 'lab-b' }
    ] }, false, replay);
  const mismatchedChallenge = {
    ...challenge, issued_at: new Date(Date.parse(challenge.issued_at) - 1000).toISOString()
  };
  await compare('different-held-challenge', witnessQuorum, witnessPolicy, false,
    { bundle, challenge: mismatchedChallenge });
  const tamperedBundle = structuredClone(bundle);
  tamperedBundle.created_at = '2030-01-01T00:00:00.000Z';
  await compare('tampered-witness', witnessQuorum, witnessPolicy, false,
    { bundle: tamperedBundle, challenge });
  const differentBundle = structuredClone(tamperedBundle);
  differentBundle.integrity.value = await sha256Browser(witnessBundlePayload(differentBundle));
  await compare('valid-witness-wrong-artifact', witnessQuorum, witnessPolicy, false,
    { bundle: differentBundle, challenge });
  const invalidReceiptProfile = structuredClone(bundle);
  invalidReceiptProfile.evidence.receipt.integrity.canonicalization = 'untrusted-profile';
  invalidReceiptProfile.evidence.integrity.value = await sha256Browser(
    Object.fromEntries(Object.entries(invalidReceiptProfile.evidence).filter(([key]) => key !== 'integrity'))
  );
  invalidReceiptProfile.integrity.value = await sha256Browser(witnessBundlePayload(invalidReceiptProfile));
  await compare('invalid-receipt-profile', witnessQuorum, witnessPolicy, false,
    { bundle: invalidReceiptProfile, challenge });

  const unauthenticatedClaim = structuredClone(witnessA);
  unauthenticatedClaim.report.session_key_fingerprint = '0'.repeat(64);
  await compare('unauthenticated-claim-ignored',
    await createSignedVerificationQuorum([witnessA, witnessB, unauthenticatedClaim], { threshold: 2 }),
    witnessPolicy, true, replay);
  for (const [name, change] of [
    ['fingerprint-conflict', value => { value.session_key_fingerprint = '0'.repeat(64); }],
    ['expiry-conflict', value => { value.challenge_expires_at = '2030-01-01T00:00:00.000Z'; }],
    ['report-before-issue', value => {
      value.checked_at = new Date(Date.parse(challenge.issued_at) - 1).toISOString();
    }],
    ['report-before-bundle', value => { value.checked_at = attestation.issued_at; }],
    ['report-after-expiry', value => {
      value.checked_at = new Date(Date.parse(challenge.expires_at) + 1).toISOString();
    }],
    ['invalid-calendar-date', value => { value.checked_at = '2030-02-30T00:00:00.000Z'; }],
    ['check-conflict', value => { value.checks.session_signature = false; }],
    ['malformed-check', value => { value.checks.challenge_binding = 'true'; }]
  ]) {
    const claim = witnessVerificationReport(bundle, witness, { verifier: name });
    change(claim);
    const conflicting = await signVerificationReport(claim, witnessKeyA);
    await compare(name,
      await createSignedVerificationQuorum([conflicting, witnessB], { threshold: 2 }),
      { ...witnessPolicy, trusted_key_fingerprints: [
        conflicting.verifier_key_fingerprint, witnessB.verifier_key_fingerprint
      ] }, false, replay);
  }
  const selfContained = await verifyWitnessBundle(bundle);
  const processClaim = witnessVerificationReport(bundle, selfContained, { verifier: 'self-contained' });
  processClaim.checks.unknown_step = false;
  const signedProcessClaim = await signVerificationReport(processClaim, witnessKeyA);
  await compare('signer-process-claim-not-inferred',
    await createSignedVerificationQuorum([signedProcessClaim, witnessB], { threshold: 2 }),
    witnessPolicy, true, replay);
  const noClaimedTime = witnessVerificationReport(bundle, witness, { verifier: 'no-claimed-time' });
  delete noClaimedTime.checked_at;
  const signedWithoutTime = await signVerificationReport(noClaimedTime, witnessKeyA);
  await compare('omitted-check-time-makes-no-time-claim',
    await createSignedVerificationQuorum([signedWithoutTime, witnessB], { threshold: 2 }),
    witnessPolicy, true, replay);

  const duplicate = JSON.stringify(quorum).replace(
    '"schema":"aml-signed-verification-quorum/1"',
    '"schema":"aml-signed-verification-quorum/1","schema":"aml-signed-verification-quorum/1"'
  );
  assert.notEqual(duplicate, JSON.stringify(quorum));
  const duplicateRun = spawnSync('python3', [python, save('duplicate.json', duplicate)], {
    encoding: 'utf8', env: { ...process.env, PYTHONDONTWRITEBYTECODE: '1' }
  });
  assert.equal(duplicateRun.status, 1, duplicateRun.stderr);
  assert.equal(JSON.parse(duplicateRun.stdout).reason, 'duplicate_json_key');

  const fractional = await signVerificationReport({ ...report('fractional'), score: 0.5 }, keyA);
  const fractionalQuorum = await createSignedVerificationQuorum([fractional], { threshold: 1 });
  assert.equal((await verifySignedVerificationQuorum(fractionalQuorum)).valid, true);
  const unsupported = spawnSync('python3',
    [python, save('fractional.json', fractionalQuorum)], { encoding: 'utf8',
      env: { ...process.env, PYTHONDONTWRITEBYTECODE: '1' } });
  assert.equal(unsupported.status, 2, unsupported.stderr);
  assert.equal(JSON.parse(unsupported.stdout).reason, 'unsupported_canonical_value');

  const malformedSignature = structuredClone(quorum);
  malformedSignature.signed_reports[0].signature = 'A';
  const malformed = spawnSync('python3',
    [python, save('malformed-signature.json', malformedSignature)], { encoding: 'utf8',
      env: { ...process.env, PYTHONDONTWRITEBYTECODE: '1' } });
  assert.equal(malformed.status, 2, malformed.stderr);
  assert.equal(JSON.parse(malformed.stdout).valid, false);
  assert.equal((await verifySignedVerificationQuorum(malformedSignature)).valid, false);

  const invalidPolicy = { ...policy, threshold: 3 };
  const usage = spawnSync('python3',
    [python, save('policy-quorum.json', quorum), '--policy', save('invalid-policy.json', invalidPolicy)],
    { encoding: 'utf8', env: { ...process.env, PYTHONDONTWRITEBYTECODE: '1' } });
  assert.equal(usage.status, 1, usage.stderr);
  assert.equal(JSON.parse(usage.stdout).reason, 'AML_SIGNED_QUORUM_POLICY_THRESHOLD_INVALID');
  const invalidGroupPolicy = { ...groupedPolicy, group_threshold: 3 };
  const invalidGroupUsage = spawnSync('python3', [python, save('group-quorum.json', quorum),
    '--policy', save('invalid-group-policy.json', invalidGroupPolicy)],
  { encoding: 'utf8', env: { ...process.env, PYTHONDONTWRITEBYTECODE: '1' } });
  assert.equal(invalidGroupUsage.status, 1, invalidGroupUsage.stderr);
  assert.equal(JSON.parse(invalidGroupUsage.stdout).reason,
    'AML_SIGNED_QUORUM_POLICY_GROUP_THRESHOLD_INVALID');

  const missingChallenge = spawnSync('python3',
    [python, save('pair-quorum.json', witnessQuorum), '--bundle', save('pair-bundle.json', bundle)],
    { encoding: 'utf8', env: { ...process.env, PYTHONDONTWRITEBYTECODE: '1' } });
  assert.equal(missingChallenge.status, 1, missingChallenge.stderr);
  assert.equal(JSON.parse(missingChallenge.stdout).reason, 'AML_SIGNED_QUORUM_WITNESS_INPUTS_REQUIRED');

  const witnessPython = path.resolve('independent/python/verify_witness.py');
  const goldenBundle = 'independent/python/witness-vector.json';
  const golden = JSON.parse(fs.readFileSync(goldenBundle, 'utf8'));
  const fixedTime = '2030-01-01T00:05:00Z';
  const heldChallenge = save('golden-held-challenge.json', golden.challenge);
  const heldRun = spawnSync('python3', [witnessPython, goldenBundle, '--now', fixedTime,
    '--challenge', heldChallenge],
    { encoding: 'utf8', env: { ...process.env, PYTHONDONTWRITEBYTECODE: '1' } });
  assert.equal(heldRun.status, 0, heldRun.stderr);
  assert.equal(JSON.parse(heldRun.stdout).valid, true);
  const changedHeld = { ...golden.challenge,
    issued_at: '2030-01-01T00:00:01.000Z' };
  const mismatchedHeld = spawnSync('python3', [witnessPython, goldenBundle, '--now', fixedTime,
    '--challenge', save('different-golden-challenge.json', changedHeld)],
    { encoding: 'utf8', env: { ...process.env, PYTHONDONTWRITEBYTECODE: '1' } });
  assert.equal(mismatchedHeld.status, 1, mismatchedHeld.stderr);
  assert.equal(JSON.parse(mismatchedHeld.stdout).reason, 'AML_PY_BUNDLE_CHALLENGE_MISMATCH');
  const duplicateWitness = fs.readFileSync(goldenBundle, 'utf8').replace(
    '"schema": "aml-witness-bundle/1",',
    '"schema": "aml-witness-bundle/1", "schema": "aml-witness-bundle/1",'
  );
  const duplicateWitnessRun = spawnSync('python3', [witnessPython,
    save('duplicate-witness.json', duplicateWitness), '--now', fixedTime],
    { encoding: 'utf8', env: { ...process.env, PYTHONDONTWRITEBYTECODE: '1' } });
  assert.equal(duplicateWitnessRun.status, 1, duplicateWitnessRun.stderr);
  assert.equal(JSON.parse(duplicateWitnessRun.stdout).reason, 'duplicate_json_key');
  const brokenSignature = structuredClone(golden);
  brokenSignature.attestation.signature = 'A';
  brokenSignature.integrity.value = await sha256Browser(witnessBundlePayload(brokenSignature));
  const brokenSignatureRun = spawnSync('python3', [witnessPython,
    save('broken-witness-signature.json', brokenSignature), '--now', fixedTime],
    { encoding: 'utf8', env: { ...process.env, PYTHONDONTWRITEBYTECODE: '1' } });
  assert.equal(brokenSignatureRun.status, 1, brokenSignatureRun.stderr);
  assert.equal(JSON.parse(brokenSignatureRun.stdout).valid, false);
  const brokenAttestation = structuredClone(golden);
  brokenAttestation.attestation = [];
  brokenAttestation.integrity.value = await sha256Browser(witnessBundlePayload(brokenAttestation));
  const brokenAttestationRun = spawnSync('python3', [witnessPython,
    save('broken-witness-attestation.json', brokenAttestation), '--now', fixedTime],
    { encoding: 'utf8', env: { ...process.env, PYTHONDONTWRITEBYTECODE: '1' } });
  assert.equal(brokenAttestationRun.status, 1, brokenAttestationRun.stderr);
  assert.equal(JSON.parse(brokenAttestationRun.stdout).reason, 'AML_PY_ATTESTATION_INVALID');
  for (const [name, now, expectedReason] of [
    ['before-issue', '2029-12-31T23:59:59Z', 'AML_PY_CHALLENGE_NOT_YET_VALID'],
    ['after-expiry', '2030-01-01T00:11:00Z', 'AML_PY_CHALLENGE_EXPIRED']
  ]) {
    const actual = spawnSync('python3', [witnessPython, goldenBundle, '--now', now],
      { encoding: 'utf8', env: { ...process.env, PYTHONDONTWRITEBYTECODE: '1' } });
    assert.equal(actual.status, 1, `${name}: ${actual.stderr}`);
    assert.equal(JSON.parse(actual.stdout).reason, expectedReason, name);
  }

  console.log(JSON.stringify({
    protocol: 'aml-signed-quorum-python-cross-runtime/1',
    passed: true, cases: checks,
    additional_checks: ['duplicate_json_key', 'fractional_canonical_value',
      'malformed_signature', 'invalid_held_policy', 'invalid_trust_group_policy',
      'dormant_key_material_alias',
      'missing_held_challenge',
      'matching_held_challenge', 'mismatched_held_challenge', 'duplicate_witness_key',
      'malformed_witness_signature', 'malformed_witness_attestation',
      'before_challenge_issue', 'after_challenge_expiry'],
    claim_boundary: 'Project-authored Python and JavaScript implementations agree on these saved quorum, held-policy, and live witness-replay cases. This is not an external witness, signer identity, or independent certification.'
  }, null, 2));
} finally {
  fs.rmSync(directory, { recursive: true, force: true });
}
