// Black-box comparison of saved JS quorums against the project-authored Python verifier.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { webcrypto } from 'node:crypto';
import { canonicalJSONStringifyBrowser, sealBrowserReceipt, sha256Browser } from '../docs/aml-browser-integrity.js';
import { browserEvidencePayload, createBrowserEvidence } from '../docs/aml-browser-evidence.js';
import { createVerificationChallenge } from '../docs/aml-verification-challenge.js';
import { createSessionAttestation } from '../docs/aml-session-attestation.js';
import { createWitnessBundle, verifyWitnessBundle, witnessBundlePayload } from '../docs/aml-witness-bundle.js';
import { witnessVerificationReport } from '../docs/aml-verification-report.js';
import { createVerifierKeyPair, signVerificationReport,
  verifySignedVerificationReport } from '../docs/aml-signed-verification-report.js';
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

async function compare(name, quorum, policy, expected, { bundle, challenge, expectedInputs } = {}) {
  const args = [python, save(`${name}-quorum.json`, quorum)];
  if (policy) args.push('--policy', save(`${name}-policy.json`, policy));
  if (bundle && challenge) args.push('--bundle', save(`${name}-bundle.json`, bundle),
    '--challenge', save(`${name}-challenge.json`, challenge));
  if (expectedInputs) args.push('--expect-inputs', save(`${name}-expected-inputs.json`, expectedInputs));
  const replayStarted = Date.now();
  const run = spawnSync('python3', args, {
    encoding: 'utf8', env: { ...process.env, PYTHONDONTWRITEBYTECODE: '1' }
  });
  if (run.error) throw run.error;
  assert.ok(run.stdout, `${name}: ${run.stderr}`);
  const py = JSON.parse(run.stdout);
  const js = await verifySignedVerificationQuorum(quorum, {
    policy, expectedInputFingerprints: expectedInputs,
    ...(bundle ? { witnessBundle: bundle, expectedChallenge: challenge } : {})
  });
  const replayFinished = Date.now();
  for (const field of ['valid', 'threshold_met', ...(policy ? ['policy_met'] : []),
    ...(bundle ? ['witness_met', 'replayable_claims_consistent'] : []),
    ...(expectedInputs ? ['inputs_met'] : []), 'requested_conditions_met']) {
    assert.equal(py[field], js[field], `${name}: ${field}: ${run.stderr} ${run.stdout}`);
  }
  assert.deepEqual(py.requested_conditions, js.requested_conditions, `${name}: requested conditions`);
  assert.equal(js.requested_conditions_met, expected, `${name}: JavaScript decision gate`);
  if (bundle) {
    for (const result of [py, js]) {
      assert.equal(result.witness_evaluation.clock_source, 'local_system', name);
      const observed = result.witness_evaluation.evaluated_at;
      assert.match(observed, /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/, name);
      assert.ok(Date.parse(observed) >= replayStarted && Date.parse(observed) <= replayFinished,
        `${name}: freshness time must come from the replay interval`);
      assert.equal(new Date(Date.parse(observed)).toISOString(), observed, name);
    }
    assert.equal(py.witness_evaluation.local_bundle_valid, js.witness_evaluation.local_bundle_valid, name);
    assert.equal(py.witness_evaluation.artifact_matches, js.witness_evaluation.artifact_matches, name);
    assert.deepEqual(py.replayable_claims_evaluation, js.replayable_claims_evaluation, name);
  }
  if (policy && js.valid) assert.deepEqual(py.policy_evaluation, js.policy_evaluation, name);
  if (expectedInputs && js.valid) assert.deepEqual(py.input_evaluation, js.input_evaluation, name);
  assert.deepEqual(py.input_fingerprints, js.input_fingerprints,
    `${name}: independently computed input fingerprints`);
  if (py.input_fingerprints) {
    assert.equal(py.input_fingerprints.quorum_sha256,
      await sha256Browser(canonicalJSONStringifyBrowser(quorum)), name);
  }
  assert.equal(py.valid && py.threshold_met && (!policy || py.policy_met) &&
    (!bundle || (py.witness_met && py.replayable_claims_consistent)) &&
    (!expectedInputs || py.inputs_met), expected, name);
  assert.equal(run.status, expected ? 0 : 2, `${name}: ${run.stderr} ${run.stdout}`);
  if (js.valid) assert.deepEqual(py.summary, js.quorum.summary, name);
  checks.push({ case: name, valid: py.valid, threshold_met: py.threshold_met,
    ...(policy ? { policy_met: py.policy_met } : {}),
    ...(bundle ? { witness_met: py.witness_met,
      replayable_claims_consistent: py.replayable_claims_consistent } : {}),
    ...(expectedInputs ? { inputs_met: py.inputs_met } : {}),
    python_matches_js: true });
  return py.input_fingerprints;
}

try {
  const fixedQuorum = JSON.parse(fs.readFileSync('independent/python/signed-quorum-vector.json', 'utf8'));
  const fixedPolicy = JSON.parse(fs.readFileSync(
    'independent/python/signed-quorum-held-policy-vector.json', 'utf8'
  ));
  // Exercise the callable Python verifier, not just its CLI. The CLI already
  // validated held inputs, so these bypasses were invisible to file-only tests.
  const directPython = String.raw`
import json, sys
sys.path.insert(0, sys.argv[3])
from verify_signed_quorum import verify_quorum
with open(sys.argv[1], encoding='utf-8') as source:
    quorum = json.load(source)
with open(sys.argv[2], encoding='utf-8') as source:
    policy = json.load(source)
zero_policy = {**policy, 'trusted_key_fingerprints': [], 'threshold': 0}
cases = {}
for name, kwargs in (
    ('zero-trust-policy', {'policy': zero_policy}),
    ('bundle-without-challenge', {'witness_bundle': {'untrusted': True}}),
    ('challenge-without-bundle', {'expected_challenge': {'untrusted': True}}),
):
    try:
        verify_quorum(quorum, **kwargs)
        cases[name] = 'ACCEPTED'
    except ValueError as error:
        cases[name] = str(error)
print(json.dumps({'valid_policy_met': verify_quorum(quorum, policy=policy)['requested_conditions_met'],
                  'rejections': cases}))`;
  const directRun = spawnSync('python3', ['-c', directPython,
    save('direct-api-quorum.json', fixedQuorum), save('direct-api-policy.json', fixedPolicy),
    path.resolve('independent/python')], {
    encoding: 'utf8', env: { ...process.env, PYTHONDONTWRITEBYTECODE: '1' }
  });
  assert.equal(directRun.status, 0, directRun.stderr);
  assert.deepEqual(JSON.parse(directRun.stdout), {
    valid_policy_met: true,
    rejections: {
      'zero-trust-policy': 'AML_SIGNED_QUORUM_POLICY_KEYS_INVALID',
      'bundle-without-challenge': 'AML_SIGNED_QUORUM_WITNESS_INPUTS_REQUIRED',
      'challenge-without-bundle': 'AML_SIGNED_QUORUM_WITNESS_INPUTS_REQUIRED'
    }
  });
  await assert.rejects(() => verifySignedVerificationQuorum(fixedQuorum, {
    policy: { ...fixedPolicy, trusted_key_fingerprints: [], threshold: 0 }
  }), /AML_SIGNED_QUORUM_POLICY_KEYS_INVALID/);
  await assert.rejects(() => verifySignedVerificationQuorum(fixedQuorum, {
    witnessBundle: { untrusted: true }
  }), /AML_SIGNED_QUORUM_WITNESS_INPUTS_REQUIRED/);
  const nullBundleRun = spawnSync('python3', [python, save('null-bundle-quorum.json', fixedQuorum),
    '--bundle', save('null-bundle.json', 'null'),
    '--challenge', save('null-bundle-challenge.json', { untrusted: true })], {
    encoding: 'utf8', env: { ...process.env, PYTHONDONTWRITEBYTECODE: '1' }
  });
  assert.equal(nullBundleRun.status, 1, nullBundleRun.stderr);
  assert.equal(JSON.parse(nullBundleRun.stdout).reason, 'AML_SIGNED_QUORUM_WITNESS_INPUTS_REQUIRED');
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
  await compare('maximum-safe-saved-threshold',
    await createSignedVerificationQuorum([a, b], { threshold: Number.MAX_SAFE_INTEGER }),
    policy, false);
  await assert.rejects(() => createSignedVerificationQuorum([a, b], {
    threshold: Number.MAX_SAFE_INTEGER + 1
  }), /AML_SIGNED_QUORUM_THRESHOLD_INVALID/);
  await compare('unsafe-saved-threshold', {
    ...quorum, threshold: Number.MAX_SAFE_INTEGER + 1
  }, policy, false);
  for (const [name, change] of [
    ['false-envelope-prototype', envelope => { envelope.prototype = false; }],
    ['missing-envelope-prototype', envelope => { delete envelope.prototype; }],
    ['unsigned-envelope-claim', envelope => {
      envelope.certified_by = 'unsigned external authority';
    }]
  ]) {
    const altered = structuredClone(quorum);
    change(altered.signed_reports[1]);
    assert.deepEqual(await verifySignedVerificationReport(altered.signed_reports[1]), {
      valid: false, reason: 'AML_SIGNED_REPORT_ENVELOPE_INVALID'
    });
    await compare(`${name}-stale-summary`, altered, policy, false);
    const rebuilt = await createSignedVerificationQuorum(altered.signed_reports, { threshold: 2 });
    assert.equal(rebuilt.summary.valid_signatures, 1);
    await compare(`${name}-recalculated-summary`, rebuilt, policy, false);
  }
  const inputExpectations = {
    schema: 'aml-signed-quorum-input-expectations/1', prototype: true,
    canonicalization: 'sorted-json-v1',
    quorum_sha256: await sha256Browser(canonicalJSONStringifyBrowser(quorum)),
    policy_sha256: await sha256Browser(canonicalJSONStringifyBrowser(policy))
  };
  await compare('held-input-pins-match', quorum, policy, true,
    { expectedInputs: inputExpectations });
  await compare('held-input-policy-substitution', quorum, {
    ...policy, trusted_key_fingerprints: [...policy.trusted_key_fingerprints].reverse()
  }, false, { expectedInputs: inputExpectations });
  await compare('held-input-quorum-substitution',
    await createSignedVerificationQuorum([b, a], { threshold: 2 }), policy, false,
    { expectedInputs: inputExpectations });
  const missingInputRun = spawnSync('python3', [python,
    save('held-input-missing-policy-quorum.json', quorum), '--expect-inputs',
    save('held-input-missing-policy-pins.json', inputExpectations)],
  { encoding: 'utf8', env: { ...process.env, PYTHONDONTWRITEBYTECODE: '1' } });
  assert.equal(missingInputRun.status, 1, missingInputRun.stderr);
  assert.equal(JSON.parse(missingInputRun.stdout).reason,
    'AML_SIGNED_QUORUM_INPUT_EXPECTATIONS_MISSING_INPUT');
  for (const [flag, error] of [
    ['--expect-inputs', 'AML_SIGNED_QUORUM_INPUT_EXPECTATIONS_INVALID'],
    ['--policy', 'AML_SIGNED_QUORUM_POLICY_INVALID']
  ]) {
    const nullRun = spawnSync('python3', [python, save(`${flag}-null-quorum.json`, quorum),
      flag, save(`${flag}-null.json`, 'null')],
    { encoding: 'utf8', env: { ...process.env, PYTHONDONTWRITEBYTECODE: '1' } });
    assert.equal(nullRun.status, 1, `${flag}: ${nullRun.stderr}`);
    assert.equal(JSON.parse(nullRun.stdout).reason, error, flag);
  }
  await assert.rejects(() => verifySignedVerificationQuorum(quorum, {
    expectedInputFingerprints: inputExpectations
  }), /AML_SIGNED_QUORUM_INPUT_EXPECTATIONS_MISSING_INPUT/);
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
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
  const last = b.signature.at(-1);
  const alternate = b.signature.slice(0, -1) + alphabet[alphabet.indexOf(last) ^ 1];
  assert.deepEqual(Buffer.from(alternate, 'base64url'), Buffer.from(b.signature, 'base64url'));
  for (const [name, signature] of [
    ['signature-unused-bits', alternate],
    ['signature-padding', `${b.signature}==`],
    ['signature-whitespace', `${b.signature.slice(0, 10)} ${b.signature.slice(10)}`],
    ['signature-truncated', b.signature.slice(0, -1)],
    ['signature-null', null]
  ]) {
    await compare(name,
      await createSignedVerificationQuorum([a, { ...b, signature }], { threshold: 2 }),
      policy, false);
  }

  const receipt = await sealBrowserReceipt({ schema: 'aml-dom-receipt/1', decisions: [] });
  const evidence = await createBrowserEvidence(receipt, { url: 'https://example.test/' });
  const challenge = createVerificationChallenge({ ttl_ms: 120000 });
  const attestation = await createSessionAttestation({ evidence, challenge });
  await new Promise(resolve => setTimeout(resolve, 10));
  const bundle = await createWitnessBundle({ evidence, challenge, attestation });
  assert.ok(Date.parse(bundle.created_at) > Date.parse(attestation.issued_at));
  const witness = await verifyWitnessBundle(bundle, { expectedChallenge: challenge });
  assert.equal(witness.valid, true);
  const secondAttestation = await createSessionAttestation({ evidence, challenge });
  assert.notEqual(secondAttestation.session_key_fingerprint,
    attestation.session_key_fingerprint);
  const secondBundle = await createWitnessBundle({ evidence, challenge,
    attestation: secondAttestation });
  assert.equal((await verifyWitnessBundle(secondBundle, { expectedChallenge: challenge })).valid,
    true);
  const secondPython = spawnSync('python3', [path.resolve('independent/python/verify_witness.py'),
    save('second-key-bundle.json', secondBundle), '--challenge',
    save('second-key-challenge.json', challenge)],
  { encoding: 'utf8', env: { ...process.env, PYTHONDONTWRITEBYTECODE: '1' } });
  assert.equal(secondPython.status, 0, secondPython.stderr);
  assert.equal(JSON.parse(secondPython.stdout).valid, true);
  const witnessKeyA = await createVerifierKeyPair();
  const witnessKeyB = await createVerifierKeyPair();
  // These adversarial cases explicitly claim a different artifact hash without
  // verifying that artifact. The report helper itself now binds a real result
  // to the bundle it inspected; replay must reject the signed false claims.
  const claimUnverifiedBundle = (candidate, verifier) => ({
    ...witnessVerificationReport(bundle, witness, { verifier }),
    artifact_hash: candidate.integrity.value
  });
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
  const timeAliasBundle = structuredClone(bundle);
  timeAliasBundle.challenge.issued_at =
    new Date(Date.parse(challenge.issued_at) + 3600000).toISOString().replace('Z', '+01:00');
  assert.equal(Date.parse(timeAliasBundle.challenge.issued_at), Date.parse(challenge.issued_at));
  timeAliasBundle.integrity.value = await sha256Browser(witnessBundlePayload(timeAliasBundle));
  const timeAliasReports = await Promise.all([witnessKeyA, witnessKeyB].map((key, index) =>
    signVerificationReport(claimUnverifiedBundle(timeAliasBundle, `time-alias-${index}`), key)));
  const timeAliasQuorum = await createSignedVerificationQuorum(timeAliasReports, { threshold: 2 });
  const timeAliasPolicy = { ...witnessPolicy, artifact_hash: timeAliasBundle.integrity.value };
  const timeAliasDecision = await verifySignedVerificationQuorum(timeAliasQuorum, {
    policy: timeAliasPolicy, witnessBundle: timeAliasBundle,
    expectedChallenge: timeAliasBundle.challenge
  });
  assert.equal(timeAliasDecision.valid, true);
  assert.equal(timeAliasDecision.threshold_met, true);
  assert.equal(timeAliasDecision.policy_met, true);
  assert.equal(timeAliasDecision.witness_met, false);
  assert.equal(timeAliasDecision.witness_evaluation.reason, 'AML_CHALLENGE_TIME_INVALID');
  await compare('signed-challenge-time-alias-rejected', timeAliasQuorum,
    timeAliasPolicy, false, { bundle: timeAliasBundle, challenge: timeAliasBundle.challenge });
  const nonceAlphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
  const nonceAlias = challenge.nonce.slice(0, -1) +
    nonceAlphabet[nonceAlphabet.indexOf(challenge.nonce.at(-1)) ^ 1];
  assert.deepEqual(Buffer.from(nonceAlias, 'base64url'), Buffer.from(challenge.nonce, 'base64url'));
  for (const [name, changedChallenge, reason] of [
    ['unexpected-challenge-claim', { ...challenge, certified_issuer: true }, 'AML_CHALLENGE_INVALID'],
    ['noncanonical-challenge-nonce', { ...challenge, nonce: nonceAlias }, 'AML_CHALLENGE_NONCE_INVALID'],
    ['text-challenge-nonce', { ...challenge, nonce: 'n'.repeat(32) }, 'AML_CHALLENGE_NONCE_INVALID']
  ]) {
    const altered = structuredClone(bundle);
    altered.challenge = changedChallenge;
    altered.integrity.value = await sha256Browser(witnessBundlePayload(altered));
    const reports = await Promise.all([witnessKeyA, witnessKeyB].map((key, index) =>
      signVerificationReport(claimUnverifiedBundle(altered, `${name}-${index}`), key)));
    const quorum = await createSignedVerificationQuorum(reports, { threshold: 2 });
    const heldPolicy = { ...witnessPolicy, artifact_hash: altered.integrity.value };
    const decision = await verifySignedVerificationQuorum(quorum, {
      policy: heldPolicy, witnessBundle: altered, expectedChallenge: changedChallenge
    });
    assert.equal(decision.valid, true, name);
    assert.equal(decision.threshold_met, true, name);
    assert.equal(decision.policy_met, true, name);
    assert.equal(decision.witness_met, false, name);
    assert.equal(decision.witness_evaluation.reason, reason, name);
    await compare(`signed-${name}-rejected`, quorum, heldPolicy, false,
      { bundle: altered, challenge: changedChallenge });
  }
  const alphabetWitness = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
  const alternateWitness = value => value.slice(0, -1) +
    alphabetWitness[alphabetWitness.indexOf(value.at(-1)) ^ 1];
  const aliasedBundle = structuredClone(bundle);
  aliasedBundle.attestation.signature = alternateWitness(bundle.attestation.signature);
  assert.deepEqual(Buffer.from(aliasedBundle.attestation.signature, 'base64url'),
    Buffer.from(bundle.attestation.signature, 'base64url'));
  aliasedBundle.integrity.value = await sha256Browser(witnessBundlePayload(aliasedBundle));
  const aliasedReports = await Promise.all([witnessKeyA, witnessKeyB].map((key, index) =>
    signVerificationReport(claimUnverifiedBundle(aliasedBundle,
      `aliased-witness-${index}`), key)));
  const aliasedQuorum = await createSignedVerificationQuorum(aliasedReports, { threshold: 2 });
  const aliasedPolicy = { ...witnessPolicy, artifact_hash: aliasedBundle.integrity.value };
  const aliasedDecision = await verifySignedVerificationQuorum(aliasedQuorum, {
    policy: aliasedPolicy, witnessBundle: aliasedBundle, expectedChallenge: challenge
  });
  assert.equal(aliasedDecision.valid, true);
  assert.equal(aliasedDecision.threshold_met, true);
  assert.equal(aliasedDecision.policy_met, true);
  assert.equal(aliasedDecision.witness_met, false);
  assert.equal(aliasedDecision.witness_evaluation.reason, 'AML_SESSION_SIGNATURE_ENCODING_INVALID');
  await compare('signed-witness-alternate-signature-rejected', aliasedQuorum, aliasedPolicy,
    false, { bundle: aliasedBundle, challenge });
  const futureBundle = structuredClone(bundle);
  futureBundle.created_at = new Date(Date.now() + 30000).toISOString();
  futureBundle.integrity.value = await sha256Browser(witnessBundlePayload(futureBundle));
  const futureA = await signVerificationReport(
    claimUnverifiedBundle(futureBundle, 'future-a'), witnessKeyA);
  const futureB = await signVerificationReport(
    claimUnverifiedBundle(futureBundle, 'future-b'), witnessKeyB);
  const futureQuorum = await createSignedVerificationQuorum([futureA, futureB], { threshold: 2 });
  const futurePolicy = {
    ...witnessPolicy, artifact_hash: futureBundle.integrity.value,
    trusted_key_fingerprints: [futureA.verifier_key_fingerprint, futureB.verifier_key_fingerprint]
  };
  const futureDecision = await verifySignedVerificationQuorum(futureQuorum, {
    policy: futurePolicy, witnessBundle: futureBundle, expectedChallenge: challenge
  });
  assert.equal(futureDecision.valid, true);
  assert.equal(futureDecision.threshold_met, true);
  assert.equal(futureDecision.policy_met, true);
  assert.equal(futureDecision.witness_evaluation.artifact_matches, true);
  assert.equal(futureDecision.witness_evaluation.reason, 'AML_WITNESS_BUNDLE_NOT_YET_CREATED');
  await compare('signed-future-bundle-rejected', futureQuorum, futurePolicy, false,
    { bundle: futureBundle, challenge });
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
  const completePolicy = {
    ...witnessGroupPolicy, schema: 'aml-signed-quorum-held-policy/4',
    require_complete_witness_claims: true,
    trusted_keys: [
      { ...await fingerprintVerifierPublicKey(witnessA.verifier_public_key_jwk), trust_group: 'lab-a' },
      { ...await fingerprintVerifierPublicKey(witnessB.verifier_public_key_jwk), trust_group: 'lab-b' }
    ]
  };
  const replayPins = {
    schema: 'aml-signed-quorum-input-expectations/1', prototype: true,
    canonicalization: 'sorted-json-v1',
    policy_sha256: await sha256Browser(canonicalJSONStringifyBrowser(completePolicy)),
    held_challenge_sha256: await sha256Browser(canonicalJSONStringifyBrowser(challenge))
  };
  await compare('held-policy-and-challenge-pins-match', witnessQuorum, completePolicy,
    true, { ...replay, expectedInputs: replayPins });
  await compare('held-challenge-pin-mismatch', witnessQuorum, completePolicy,
    false, { ...replay, expectedInputs: { ...replayPins,
      held_challenge_sha256: '0'.repeat(64) } });
  const completeInputs = await compare('complete-signed-witness-claims',
    witnessQuorum, completePolicy, true, replay);
  const vetoPolicy = { ...completePolicy, schema: 'aml-signed-quorum-held-policy/5',
    reject_trusted_dissent: true };
  const vetoInputs = await compare('veto-policy-without-dissent',
    witnessQuorum, vetoPolicy, true, replay);
  assert.notEqual(vetoInputs.policy_sha256, completeInputs.policy_sha256);
  assert.equal(vetoInputs.quorum_sha256, completeInputs.quorum_sha256);
  const requiredKey = await createVerifierKeyPair();
  const requiredReport = await signVerificationReport(
    witnessVerificationReport(bundle, witness, { verifier: 'required-lab-c' }), requiredKey);
  const requiredMaterial = await fingerprintVerifierPublicKey(requiredReport.verifier_public_key_jwk);
  const presencePolicy = {
    ...vetoPolicy, schema: 'aml-signed-quorum-held-policy/6',
    trusted_keys: [...vetoPolicy.trusted_keys, { ...requiredMaterial, trust_group: 'lab-c' }],
    required_key_material_fingerprints: [requiredMaterial.key_material_fingerprint]
  };
  await compare('required-participant-withheld', witnessQuorum, presencePolicy, false, replay);
  const withRequired = await createSignedVerificationQuorum(
    [witnessA, witnessB, requiredReport], { threshold: 2 });
  await compare('required-participant-present', withRequired, presencePolicy, true, replay);
  const requiredAlias = structuredClone(requiredReport);
  requiredAlias.verifier_public_key_jwk.kid = 'required-key-metadata-alias';
  requiredAlias.verifier_key_fingerprint = await sha256Browser(requiredAlias.verifier_public_key_jwk);
  await compare('required-participant-metadata-alias',
    await createSignedVerificationQuorum([witnessA, witnessB, requiredAlias], { threshold: 2 }),
    presencePolicy, true, replay);
  const sparseRequired = witnessVerificationReport(bundle, witness, { verifier: 'sparse-required' });
  sparseRequired.checks = {};
  const sparseRequiredAlias = await signVerificationReport(sparseRequired, requiredKey);
  sparseRequiredAlias.verifier_public_key_jwk.kid = 'sparse-required-key-alias';
  sparseRequiredAlias.verifier_key_fingerprint = await sha256Browser(
    sparseRequiredAlias.verifier_public_key_jwk);
  const sparseRequiredQuorum = await createSignedVerificationQuorum(
    [witnessA, witnessB, sparseRequiredAlias], { threshold: 2 });
  await compare('sparse-required-alias-older-policy', sparseRequiredQuorum, vetoPolicy, true, replay);
  await compare('sparse-required-alias-rejected', sparseRequiredQuorum, presencePolicy, false, replay);
  const unsignedRequired = { ...requiredReport,
    report: { ...requiredReport.report, reason: 'changed-after-signing' } };
  await compare('required-participant-invalid-signature',
    await createSignedVerificationQuorum([witnessA, witnessB, unsignedRequired], { threshold: 2 }),
    presencePolicy, false, replay);
  const requiredNegative = { ...witnessVerificationReport(bundle, witness,
    { verifier: 'required-lab-c-dissent' }), valid: false, reason: 'AML_TEST_SIGNED_DISSENT' };
  await compare('required-participant-dissent-veto',
    await createSignedVerificationQuorum([witnessA, witnessB,
      await signVerificationReport(requiredNegative, requiredKey)], { threshold: 2 }),
    presencePolicy, false, replay);
  for (const invalidRequired of [[], [requiredMaterial.key_material_fingerprint,
    requiredMaterial.key_material_fingerprint], ['0'.repeat(64)]]) {
    assert.throws(() => validateSignedVerificationQuorumPolicy({
      ...presencePolicy, required_key_material_fingerprints: invalidRequired
    }), /AML_SIGNED_QUORUM_POLICY_REQUIRED_KEYS_INVALID/);
    const invalidRun = spawnSync('python3', [python,
      save('invalid-required-quorum.json', withRequired), '--policy',
      save('invalid-required-policy.json', {
        ...presencePolicy, required_key_material_fingerprints: invalidRequired
      })], { encoding: 'utf8', env: { ...process.env, PYTHONDONTWRITEBYTECODE: '1' } });
    assert.equal(invalidRun.status, 1, invalidRun.stderr);
    assert.equal(JSON.parse(invalidRun.stdout).reason,
      'AML_SIGNED_QUORUM_POLICY_REQUIRED_KEYS_INVALID');
  }
  const noRequiredWitness = spawnSync('python3', [python,
    save('presence-without-bundle.json', withRequired), '--policy',
    save('presence-without-bundle-policy.json', presencePolicy)],
  { encoding: 'utf8', env: { ...process.env, PYTHONDONTWRITEBYTECODE: '1' } });
  assert.equal(noRequiredWitness.status, 1, noRequiredWitness.stderr);
  assert.equal(JSON.parse(noRequiredWitness.stdout).reason,
    'AML_SIGNED_QUORUM_POLICY_WITNESS_REQUIRED');
  const negative = witnessVerificationReport(bundle, witness, { verifier: 'witness-b-dissent' });
  negative.valid = false;
  negative.reason = 'AML_TEST_SIGNED_DISSENT';
  const signedDissent = await signVerificationReport(negative, witnessKeyB);
  const withDissent = await createSignedVerificationQuorum(
    [witnessA, witnessB, signedDissent], { threshold: 2 });
  await compare('trusted-dissent-older-policy', withDissent, completePolicy, true, replay);
  await compare('trusted-dissent-veto', withDissent, vetoPolicy, false, replay);
  const aliasDissent = structuredClone(signedDissent);
  aliasDissent.verifier_public_key_jwk.kid = 'same-key-different-envelope';
  aliasDissent.verifier_key_fingerprint = await sha256Browser(aliasDissent.verifier_public_key_jwk);
  assert.notEqual(aliasDissent.verifier_key_fingerprint, signedDissent.verifier_key_fingerprint);
  await compare('trusted-dissent-metadata-alias-veto',
    await createSignedVerificationQuorum([witnessA, witnessB, aliasDissent], { threshold: 2 }),
    vetoPolicy, false, replay);
  const outsiderDissent = await signVerificationReport(negative, await createVerifierKeyPair());
  await compare('untrusted-dissent-cannot-veto',
    await createSignedVerificationQuorum([witnessA, witnessB, outsiderDissent], { threshold: 2 }),
    vetoPolicy, true, replay);
  await compare('unauthenticated-dissent-cannot-veto',
    await createSignedVerificationQuorum([witnessA, witnessB,
      { ...signedDissent, report: { ...negative, reason: 'changed-without-resigning' } }
    ], { threshold: 2 }), vetoPolicy, true, replay);
  assert.throws(() => validateSignedVerificationQuorumPolicy({
    ...vetoPolicy, reject_trusted_dissent: false
  }), /AML_SIGNED_QUORUM_POLICY_INVALID/);
  const missingVetoReplay = spawnSync('python3', [python,
    save('veto-without-bundle.json', witnessQuorum),
    '--policy', save('veto-without-bundle-policy.json', vetoPolicy)],
  { encoding: 'utf8', env: { ...process.env, PYTHONDONTWRITEBYTECODE: '1' } });
  assert.equal(missingVetoReplay.status, 1, missingVetoReplay.stderr);
  assert.equal(JSON.parse(missingVetoReplay.stdout).reason, 'AML_SIGNED_QUORUM_POLICY_WITNESS_REQUIRED');
  const malformedVetoRun = spawnSync('python3', [python,
    save('malformed-veto-quorum.json', witnessQuorum), '--policy',
    save('malformed-veto-policy.json', { ...vetoPolicy, reject_trusted_dissent: false })],
  { encoding: 'utf8', env: { ...process.env, PYTHONDONTWRITEBYTECODE: '1' } });
  assert.equal(malformedVetoRun.status, 1, malformedVetoRun.stderr);
  assert.equal(JSON.parse(malformedVetoRun.stdout).reason, 'AML_SIGNED_QUORUM_POLICY_INVALID');
  const belowSavedThreshold = await createSignedVerificationQuorum([witnessA, witnessB],
    { threshold: 3 });
  const heldVsSaved = await verifySignedVerificationQuorum(belowSavedThreshold, {
    policy: completePolicy, witnessBundle: bundle, expectedChallenge: challenge
  });
  assert.equal(heldVsSaved.valid, true);
  assert.equal(heldVsSaved.threshold_met, false);
  assert.equal(heldVsSaved.policy_met, true);
  await compare('complete-held-policy-met-but-saved-threshold-unmet', belowSavedThreshold,
    completePolicy, false, replay);
  const vetoBelowSaved = await verifySignedVerificationQuorum(belowSavedThreshold, {
    policy: vetoPolicy, witnessBundle: bundle, expectedChallenge: challenge
  });
  assert.equal(vetoBelowSaved.valid, true);
  assert.equal(vetoBelowSaved.threshold_met, false);
  assert.equal(vetoBelowSaved.policy_met, true);
  await compare('veto-held-policy-met-but-saved-threshold-unmet', belowSavedThreshold,
    vetoPolicy, false, replay);
  const noChecks = witnessVerificationReport(bundle, witness, { verifier: 'no-checks' });
  noChecks.checks = {};
  const sparseA = await signVerificationReport(noChecks, witnessKeyA);
  const sparseQuorum = await createSignedVerificationQuorum([sparseA, witnessB], { threshold: 2 });
  await compare('sparse-signed-claims-older-policy', sparseQuorum, witnessPolicy, true, replay);
  await compare('sparse-signed-claims-required', sparseQuorum, completePolicy, false, replay);
  const noTime = witnessVerificationReport(bundle, witness, { verifier: 'no-time' });
  delete noTime.checked_at;
  await compare('missing-signed-time-required',
    await createSignedVerificationQuorum([
      await signVerificationReport(noTime, witnessKeyA), witnessB
    ], { threshold: 2 }), completePolicy, false, replay);
  const falseProcess = witnessVerificationReport(bundle, witness, { verifier: 'false-process' });
  falseProcess.checks.verifier_held_challenge = false;
  await compare('missing-affirmative-process-claim',
    await createSignedVerificationQuorum([
      await signVerificationReport(falseProcess, witnessKeyA), witnessB
    ], { threshold: 2 }), completePolicy, false, replay);
  const untrustedSparse = await signVerificationReport(noChecks, await createVerifierKeyPair());
  await compare('untrusted-sparse-report-not-required',
    await createSignedVerificationQuorum([witnessA, witnessB, untrustedSparse], { threshold: 2 }),
    completePolicy, true, replay);
  const changedChallengeInputs = await compare('complete-claims-wrong-challenge',
    witnessQuorum, completePolicy, false,
    { bundle, challenge: { ...challenge,
      issued_at: new Date(Date.parse(challenge.issued_at) - 1000).toISOString() } });
  assert.equal(changedChallengeInputs.quorum_sha256, completeInputs.quorum_sha256);
  assert.equal(changedChallengeInputs.policy_sha256, completeInputs.policy_sha256);
  assert.notEqual(changedChallengeInputs.held_challenge_sha256,
    completeInputs.held_challenge_sha256);
  const missingReplayRun = spawnSync('python3', [python, save('complete-without-bundle.json', witnessQuorum),
    '--policy', save('complete-without-bundle-policy.json', completePolicy)],
  { encoding: 'utf8', env: { ...process.env, PYTHONDONTWRITEBYTECODE: '1' } });
  assert.equal(missingReplayRun.status, 1, missingReplayRun.stderr);
  assert.equal(JSON.parse(missingReplayRun.stdout).reason, 'AML_SIGNED_QUORUM_POLICY_WITNESS_REQUIRED');
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
  differentBundle.created_at = new Date(Date.parse(bundle.created_at) + 1).toISOString();
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
    ['report-after-replay', value => {
      value.checked_at = new Date(Date.now() + 30000).toISOString();
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
  assert.equal((await verifyWitnessBundle(golden, {
    expectedChallenge: golden.challenge, now: Date.parse(fixedTime)
  })).valid, true);
  // The old JS parser normalized November 31 to December 1. The signed
  // session and bundle remain intact when only the unsigned challenge issue
  // spelling changes, so this used to yield a different decision in Python.
  for (const [name, field, value] of [
    ['challenge-calendar-rollover', 'issued_at', '2029-11-31T00:00:02.000Z'],
    ['challenge-offset-alias', 'issued_at', '2030-01-01T01:00:02.000+01:00'],
    ['challenge-submillisecond', 'issued_at', '2030-01-01T00:00:02.0001Z'],
    ['challenge-missing-milliseconds', 'expires_at', '2030-01-01T00:10:02Z']
  ]) {
    const altered = structuredClone(golden);
    altered.challenge[field] = value;
    altered.integrity.value = await sha256Browser(witnessBundlePayload(altered));
    const held = save(`${name}-challenge.json`, altered.challenge);
    const pathToBundle = save(`${name}-bundle.json`, altered);
    const jsResult = await verifyWitnessBundle(altered, {
      expectedChallenge: altered.challenge, now: Date.parse(fixedTime)
    });
    assert.equal(jsResult.reason, 'AML_CHALLENGE_TIME_INVALID', name);
    const pyRun = spawnSync('python3', [witnessPython, pathToBundle,
      '--challenge', held, '--now', fixedTime],
    { encoding: 'utf8', env: { ...process.env, PYTHONDONTWRITEBYTECODE: '1' } });
    assert.equal(pyRun.status, 1, `${name}: ${pyRun.stderr}`);
    assert.equal(JSON.parse(pyRun.stdout).reason, 'AML_PY_CHALLENGE_TIME_INVALID', name);
  }
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
  // Preserve the signed bytes while changing only their textual spelling.
  // A permissive base64 decoder must not make JS accept what Python rejects.
  for (const [name, change, jsReason, pyReason] of [
    ['unused-signature-bits', value => {
      const signature = value.attestation.signature;
      value.attestation.signature = alternateWitness(signature);
      assert.deepEqual(Buffer.from(value.attestation.signature, 'base64url'),
        Buffer.from(signature, 'base64url'));
    }, 'AML_SESSION_SIGNATURE_ENCODING_INVALID', 'AML_PY_SIGNATURE_ENCODING_UNSUPPORTED'],
    ['padded-signature', value => {
      value.attestation.signature += '==';
    }, 'AML_SESSION_SIGNATURE_ENCODING_INVALID', 'AML_PY_SIGNATURE_ENCODING_UNSUPPORTED'],
    ['alternate-key-coordinate', value => {
      const jwk = value.attestation.session_public_key_jwk;
      const x = jwk.x;
      jwk.x = alternateWitness(x);
      assert.deepEqual(Buffer.from(jwk.x, 'base64url'), Buffer.from(x, 'base64url'));
    }, 'AML_SESSION_KEY_ENCODING_INVALID', 'AML_PY_KEY_FINGERPRINT_MISMATCH']
  ]) {
    const altered = structuredClone(golden);
    change(altered);
    altered.integrity.value = await sha256Browser(witnessBundlePayload(altered));
    const jsResult = await verifyWitnessBundle(altered, {
      expectedChallenge: golden.challenge, now: Date.parse(fixedTime)
    });
    assert.equal(jsResult.reason, jsReason, name);
    const pyRun = spawnSync('python3', [witnessPython,
      save(`${name}-bundle.json`, altered), '--challenge', heldChallenge, '--now', fixedTime],
    { encoding: 'utf8', env: { ...process.env, PYTHONDONTWRITEBYTECODE: '1' } });
    assert.equal(pyRun.status, 1, `${name}: ${pyRun.stderr}`);
    assert.equal(JSON.parse(pyRun.stdout).reason, pyReason, name);
  }
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

  // A fixed, signed 2030 vector tests chronology without racing the machine
  // clock. Resealing a bundle is possible for its producer, but cannot turn
  // an impossible timeline into a successful witness replay.
  for (const [name, change, jsReason, pyReason] of [
    ['invalid-bundle-calendar', value => { value.created_at = '2030-02-30T00:00:00.000Z'; },
      'AML_WITNESS_BUNDLE_TIME_INVALID', 'AML_PY_BUNDLE_TIME_INVALID'],
    ['bundle-before-attestation', value => { value.created_at = '2030-01-01T00:00:02.999Z'; },
      'AML_WITNESS_BUNDLE_TIME_ORDER_INVALID', 'AML_PY_BUNDLE_TIME_ORDER_INVALID'],
    ['bundle-after-expiry', value => { value.created_at = '2030-01-01T00:10:02.001Z'; },
      'AML_WITNESS_BUNDLE_TIME_ORDER_INVALID', 'AML_PY_BUNDLE_TIME_ORDER_INVALID'],
    ['bundle-after-replay', value => { value.created_at = '2030-01-01T00:06:00.000Z'; },
      'AML_WITNESS_BUNDLE_NOT_YET_CREATED', 'AML_PY_BUNDLE_NOT_YET_CREATED'],
    ['attestation-before-challenge', value => {
      value.challenge.issued_at = '2030-01-01T00:00:03.001Z';
    }, 'AML_WITNESS_BUNDLE_TIME_ORDER_INVALID', 'AML_PY_BUNDLE_TIME_ORDER_INVALID']
  ]) {
    const altered = structuredClone(golden);
    change(altered);
    altered.integrity.value = await sha256Browser(witnessBundlePayload(altered));
    const held = save(`${name}-challenge.json`, altered.challenge);
    const pathToBundle = save(`${name}-bundle.json`, altered);
    const pyRun = spawnSync('python3', [witnessPython, pathToBundle,
      '--challenge', held, '--now', fixedTime],
    { encoding: 'utf8', env: { ...process.env, PYTHONDONTWRITEBYTECODE: '1' } });
    assert.equal(pyRun.status, 1, `${name}: ${pyRun.stderr}`);
    assert.equal(JSON.parse(pyRun.stdout).reason, pyReason, name);
    const jsResult = await verifyWitnessBundle(altered, {
      expectedChallenge: altered.challenge, now: Date.parse(fixedTime)
    });
    assert.equal(jsResult.reason, jsReason, name);
  }

  // Sign altered evidence afresh so both runtimes reach the chronology check
  // after all hashes and the session signature pass.
  for (const [name, receiptTime, evidenceTime, jsReason, pyReason] of [
    ['receipt-after-evidence', 'future', 'current',
      'AML_WITNESS_BUNDLE_TIME_ORDER_INVALID', 'AML_PY_BUNDLE_TIME_ORDER_INVALID'],
    ['evidence-after-attestation', 'past', 'future',
      'AML_WITNESS_BUNDLE_TIME_ORDER_INVALID', 'AML_PY_BUNDLE_TIME_ORDER_INVALID'],
    ['malformed-receipt-time', 'malformed', 'current',
      'AML_WITNESS_BUNDLE_TIME_INVALID', 'AML_PY_BUNDLE_TIME_INVALID'],
    ['missing-evidence-time', 'past', 'missing',
      'AML_WITNESS_BUNDLE_TIME_INVALID', 'AML_PY_BUNDLE_TIME_INVALID']
  ]) {
    const receipt = await sealBrowserReceipt({ schema: 'aml-dom-receipt/1', decisions: [],
      generated_at: receiptTime === 'future' ? new Date(Date.now() + 30000).toISOString() :
        receiptTime === 'malformed' ? '2030-02-30T00:00:00.000Z' :
          new Date(Date.now() - 1000).toISOString() });
    const candidateEvidence = await createBrowserEvidence(receipt, { url: 'https://example.test/' });
    if (evidenceTime === 'future') {
      candidateEvidence.generated_at = new Date(Date.now() + 30000).toISOString();
    } else if (evidenceTime === 'missing') {
      delete candidateEvidence.generated_at;
    }
    candidateEvidence.integrity.value = await sha256Browser(browserEvidencePayload(candidateEvidence));
    const candidateChallenge = createVerificationChallenge({ ttl_ms: 120000 });
    const candidateAttestation = await createSessionAttestation({
      evidence: candidateEvidence, challenge: candidateChallenge
    });
    const candidateBundle = {
      schema: 'aml-witness-bundle/1', prototype: true, created_at: new Date().toISOString(),
      evidence: candidateEvidence, challenge: candidateChallenge, attestation: candidateAttestation
    };
    candidateBundle.integrity = { schema: 'aml-integrity/1', algorithm: 'SHA-256',
      canonicalization: 'sorted-json-v1',
      value: await sha256Browser(witnessBundlePayload(candidateBundle)) };
    const jsResult = await verifyWitnessBundle(candidateBundle, {
      expectedChallenge: candidateChallenge
    });
    assert.equal(jsResult.reason, jsReason, name);
    assert.equal(jsResult.checks.session_signature, true, name);
    const pyRun = spawnSync('python3', [witnessPython,
      save(`${name}-bundle.json`, candidateBundle), '--challenge',
      save(`${name}-challenge.json`, candidateChallenge)],
    { encoding: 'utf8', env: { ...process.env, PYTHONDONTWRITEBYTECODE: '1' } });
    assert.equal(pyRun.status, 1, `${name}: ${pyRun.stderr}`);
    assert.equal(JSON.parse(pyRun.stdout).reason, pyReason, name);
  }

  console.log(JSON.stringify({
    protocol: 'aml-signed-quorum-python-cross-runtime/1',
    passed: true, cases: checks,
    additional_checks: ['duplicate_json_key', 'fractional_canonical_value',
      'malformed_signature', 'invalid_held_policy', 'invalid_trust_group_policy',
      'dormant_key_material_alias', 'complete_claims_without_witness',
      'veto_policy_without_witness', 'invalid_veto_policy',
      'missing_held_challenge',
      'matching_held_challenge', 'mismatched_held_challenge', 'duplicate_witness_key',
      'malformed_witness_signature', 'malformed_witness_attestation',
      'witness_unused_signature_bits', 'witness_padded_signature',
      'witness_alternate_key_coordinate',
      'fresh_second_attestation_key_python_replay',
      'challenge_calendar_rollover', 'challenge_offset_alias',
      'challenge_submillisecond', 'challenge_missing_milliseconds',
      'before_challenge_issue', 'after_challenge_expiry',
      'fixed_vector_bundle_calendar', 'fixed_vector_bundle_before_attestation',
      'fixed_vector_bundle_after_expiry', 'fixed_vector_bundle_after_replay',
      'fixed_vector_attestation_before_challenge',
      'signed_receipt_after_evidence', 'signed_evidence_after_attestation',
      'signed_malformed_receipt_time', 'signed_missing_evidence_time',
      'null_input_expectations_rejected', 'null_held_policy_rejected',
      'direct_api_rejects_zero_trust_policy', 'direct_api_requires_paired_witness_inputs',
      'cli_rejects_null_bundle_without_traceback'],
    claim_boundary: 'Project-authored Python and JavaScript implementations agree on these saved quorum, held-policy, and live witness-replay cases. This is not an external witness, signer identity, or independent certification.'
  }, null, 2));
} finally {
  fs.rmSync(directory, { recursive: true, force: true });
}
