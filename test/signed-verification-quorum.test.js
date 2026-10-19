import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { webcrypto } from 'node:crypto';
import { canonicalJSONStringifyBrowser, sha256Browser } from '../docs/aml-browser-integrity.js';

if (!globalThis.crypto) globalThis.crypto = webcrypto;
if (!globalThis.btoa) globalThis.btoa = (value) => Buffer.from(value, 'binary').toString('base64');
if (!globalThis.atob) globalThis.atob = (value) => Buffer.from(value, 'base64').toString('binary');

import {
  createVerifierKeyPair,
  signVerificationReport,
  verifySignedVerificationReport
} from '../docs/aml-signed-verification-report.js';
import {
  createSignedVerificationQuorum,
  fingerprintVerifierPublicKey,
  verifySignedVerificationQuorum
} from '../docs/aml-signed-verification-quorum.js';

function report(verifier, artifactHash = 'a'.repeat(64), valid = true) {
  return {
    schema: 'aml-verification-report/1',
    prototype: true,
    verifier,
    artifact_type: 'aml-witness-bundle/1',
    valid,
    reason: valid ? 'AML_WITNESS_BUNDLE_VALID' : 'AML_SESSION_SIGNATURE_INVALID',
    checked_at: '2030-01-01T00:05:00.000Z',
    artifact_hash: artifactHash,
    session_key_fingerprint: null,
    challenge_expires_at: '2030-01-01T00:10:00.000Z',
    checks: { bundle_integrity: true, session_signature: valid },
    notes: []
  };
}

test('signed verification report detects report mutation', async () => {
  const keys = await createVerifierKeyPair();
  const envelope = await signVerificationReport(report('verifier-a'), keys);
  assert.equal((await verifySignedVerificationReport(envelope)).valid, true);

  const tampered = structuredClone(envelope);
  tampered.report.valid = false;
  const check = await verifySignedVerificationReport(tampered);
  assert.equal(check.valid, false);
  assert.equal(check.reason, 'AML_SIGNED_REPORT_SIGNATURE_INVALID');
});

test('unsigned envelope changes cannot retain a signed endorsement', async () => {
  const a = await signVerificationReport(report('envelope-a'), await createVerifierKeyPair());
  const b = await signVerificationReport(report('envelope-b'), await createVerifierKeyPair());
  const saved = await createSignedVerificationQuorum([a, b], { threshold: 2 });

  for (const change of [
    envelope => { envelope.prototype = false; },
    envelope => { delete envelope.prototype; },
    envelope => { envelope.certified_by = 'unsigned external authority'; }
  ]) {
    const altered = structuredClone(saved);
    change(altered.signed_reports[1]);
    assert.deepEqual(await verifySignedVerificationReport(altered.signed_reports[1]), {
      valid: false, reason: 'AML_SIGNED_REPORT_ENVELOPE_INVALID'
    });
    const stale = await verifySignedVerificationQuorum(altered);
    assert.equal(stale.valid, false);
    assert.equal(stale.threshold_met, false);

    const rebuilt = await createSignedVerificationQuorum(altered.signed_reports, { threshold: 2 });
    const checked = await verifySignedVerificationQuorum(rebuilt);
    assert.equal(checked.valid, true);
    assert.equal(checked.threshold_met, false);
    assert.equal(checked.quorum.summary.valid_signatures, 1);
    assert.equal(checked.requested_conditions_met, false);
  }
});

test('signing and signature checks use the JSON supplied at call time', async () => {
  const keys = await createVerifierKeyPair();
  const source = report('original-verifier');
  const signing = signVerificationReport(source, keys);
  source.verifier = 'changed-during-signing';
  const envelope = await signing;
  assert.equal(envelope.report.verifier, 'original-verifier');
  assert.equal((await verifySignedVerificationReport(envelope)).valid, true);

  const checking = verifySignedVerificationReport(envelope);
  envelope.report.verifier = 'changed-during-verification';
  const result = await checking;
  assert.equal(result.valid, true);
  assert.equal(result.verifier, 'original-verifier');
  assert.equal((await verifySignedVerificationReport(envelope)).valid, false);
});

test('rejects alternate base64url spellings of the same P-256 public point', async () => {
  const envelope = await signVerificationReport(report('canonical-key'), await createVerifierKeyPair());
  const altered = structuredClone(envelope);
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
  const original = altered.verifier_public_key_jwk.x;
  const index = alphabet.indexOf(original.at(-1));
  altered.verifier_public_key_jwk.x = original.slice(0, -1) + alphabet[index ^ 1];
  altered.verifier_key_fingerprint = await sha256Browser(altered.verifier_public_key_jwk);
  assert.notEqual(altered.verifier_key_fingerprint, envelope.verifier_key_fingerprint);
  const verdict = await verifySignedVerificationReport(altered);
  assert.deepEqual(verdict, { valid: false, reason: 'AML_SIGNED_REPORT_KEY_ENCODING_INVALID' });
  await assert.rejects(() => fingerprintVerifierPublicKey(altered.verifier_public_key_jwk),
    /AML_SIGNED_REPORT_KEY_ENCODING_INVALID/);
});

test('public-key fingerprints identify the key document supplied at call time', async () => {
  const envelope = await signVerificationReport(report('key-owner'), await createVerifierKeyPair());
  const jwk = structuredClone(envelope.verifier_public_key_jwk);
  const fingerprinting = fingerprintVerifierPublicKey(jwk);
  jwk.kid = 'added-after-call';
  const fingerprints = await fingerprinting;
  assert.equal(fingerprints.verifier_key_fingerprint, envelope.verifier_key_fingerprint);
  assert.notEqual((await fingerprintVerifierPublicKey(jwk)).verifier_key_fingerprint,
    fingerprints.verifier_key_fingerprint);
});

test('rejects alternate text spellings of a valid P-256 report signature', async () => {
  const a = await signVerificationReport(report('canonical-signature-a'), await createVerifierKeyPair());
  const b = await signVerificationReport(report('canonical-signature-b'), await createVerifierKeyPair());
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
  const last = b.signature.at(-1);
  const alternate = b.signature.slice(0, -1) + alphabet[alphabet.indexOf(last) ^ 1];
  assert.notEqual(alternate, b.signature);
  assert.deepEqual(Buffer.from(alternate, 'base64url'), Buffer.from(b.signature, 'base64url'));

  for (const signature of [alternate, `${b.signature}==`,
    `${b.signature.slice(0, 20)} ${b.signature.slice(20)}`, b.signature.slice(0, -1), null]) {
    const mutated = { ...b, signature };
    assert.deepEqual(await verifySignedVerificationReport(mutated), {
      valid: false, reason: 'AML_SIGNED_REPORT_SIGNATURE_ENCODING_INVALID'
    });
    const quorum = await createSignedVerificationQuorum([a, mutated], { threshold: 2 });
    assert.equal(quorum.summary.valid_signatures, 1);
    assert.equal(quorum.summary.threshold_met, false);
    const checked = await verifySignedVerificationQuorum(JSON.parse(JSON.stringify(quorum)));
    assert.equal(checked.valid, true);
    assert.equal(checked.threshold_met, false);
  }
  assert.equal((await verifySignedVerificationReport(b)).valid, true);
});

test('signed reports reject live claims that the signature did not cover', async () => {
  const keys = await createVerifierKeyPair();
  const envelope = await signVerificationReport(report('verifier-a'), keys);
  Object.defineProperty(envelope.report, 'unbound_claim', { value: 'approved by external auditor' });
  const check = await verifySignedVerificationReport(envelope);
  assert.equal(check.valid, false);
  assert.equal(check.reason, 'AML_CANONICAL_JSON_NON_JSON_OBJECT');
  await assert.rejects(
    () => createSignedVerificationQuorum([envelope], { threshold: 1 }),
    /AML_CANONICAL_JSON_NON_JSON_OBJECT/
  );
  await assert.rejects(
    () => signVerificationReport(envelope.report, keys),
    /AML_CANONICAL_JSON_NON_JSON_OBJECT/
  );
});

test('signed verification quorum requires distinct valid key fingerprints', async () => {
  const keyA = await createVerifierKeyPair();
  const keyB = await createVerifierKeyPair();
  const envelopeA = await signVerificationReport(report('verifier-a'), keyA);
  const envelopeB = await signVerificationReport(report('verifier-b'), keyB);
  const quorum = await createSignedVerificationQuorum([envelopeA, envelopeB], { threshold: 2 });
  assert.equal(quorum.summary.distinct_keys, 2);
  assert.equal(quorum.summary.valid_reports, 2);
  assert.equal(quorum.summary.threshold_met, true);
  assert.equal(quorum.summary.unanimous, true);
});

test('saved signed thresholds stay within the portable safe-integer range', async () => {
  const signed = await signVerificationReport(report('safe-threshold'), await createVerifierKeyPair());
  const boundary = await createSignedVerificationQuorum([signed], {
    threshold: Number.MAX_SAFE_INTEGER
  });
  const checked = await verifySignedVerificationQuorum(boundary);
  assert.equal(checked.valid, true);
  assert.equal(checked.threshold_met, false);
  await assert.rejects(() => createSignedVerificationQuorum([signed], {
    threshold: Number.MAX_SAFE_INTEGER + 1
  }), /AML_SIGNED_QUORUM_THRESHOLD_INVALID/);
  const unsafe = { ...boundary, threshold: Number.MAX_SAFE_INTEGER + 1 };
  const rejected = await verifySignedVerificationQuorum(unsafe);
  assert.equal(rejected.valid, false);
  assert.equal(rejected.threshold_met, false);
});

test('quorum creation counts the signed report snapshot despite live mutations', async () => {
  const a = await signVerificationReport(report('a'), await createVerifierKeyPair());
  const b = await signVerificationReport(report('b'), await createVerifierKeyPair());
  const submitted = [a, b];
  const creating = createSignedVerificationQuorum(submitted, { threshold: 2 });
  a.report.valid = false;
  b.report.artifact_hash = 'b'.repeat(64);
  submitted.push({ bogus: true });
  const quorum = await creating;
  assert.equal(quorum.signed_reports.length, 2);
  assert.equal(quorum.signed_reports[0].report.valid, true);
  assert.equal(quorum.signed_reports[1].report.artifact_hash, 'a'.repeat(64));
  assert.equal(quorum.summary.threshold_met, true);
  assert.equal((await verifySignedVerificationQuorum(quorum)).valid, true);
});

test('saved signed quorum recomputes signatures, summary, threshold, and claim boundary', async () => {
  const envelopeA = await signVerificationReport(report('verifier-a'), await createVerifierKeyPair());
  const envelopeB = await signVerificationReport(report('verifier-b'), await createVerifierKeyPair());
  const quorum = await createSignedVerificationQuorum([envelopeA, envelopeB], { threshold: 2 });
  const saved = JSON.parse(JSON.stringify(quorum));
  const verified = await verifySignedVerificationQuorum(saved);
  assert.equal(verified.valid, true);
  assert.equal(verified.threshold_met, true);
  assert.equal(verified.requested_conditions_met, true);
  assert.deepEqual(verified.requested_conditions, {
    checked: ['valid', 'threshold_met'], unmet: []
  });

  const wrongSchema = await verifySignedVerificationQuorum({ schema: 'other-quorum/1' });
  assert.equal(wrongSchema.valid, false);
  assert.equal(wrongSchema.threshold_met, false);
  assert.deepEqual(wrongSchema.requested_conditions, {
    checked: ['valid', 'threshold_met'], unmet: ['valid', 'threshold_met']
  });

  const inflated = structuredClone(saved);
  inflated.summary.distinct_keys = 3;
  assert.equal((await verifySignedVerificationQuorum(inflated)).reason, 'AML_SIGNED_QUORUM_MISMATCH');

  const rewritten = structuredClone(saved);
  rewritten.claim_boundary = 'Certified by an independent authority';
  assert.equal((await verifySignedVerificationQuorum(rewritten)).valid, false);

  const changedReport = structuredClone(saved);
  changedReport.signed_reports[0].report.reason = 'changed after signing';
  assert.equal((await verifySignedVerificationQuorum(changedReport)).valid, false);

  const hiddenClaim = structuredClone(saved);
  Object.defineProperty(hiddenClaim, 'approval', { value: 'unbound' });
  assert.equal((await verifySignedVerificationQuorum(hiddenClaim)).reason, 'AML_CANONICAL_JSON_NON_JSON_OBJECT');
});

test('held policy and saved quorum remain one coherent replay snapshot', async () => {
  const a = await signVerificationReport(report('a'), await createVerifierKeyPair());
  const b = await signVerificationReport(report('b'), await createVerifierKeyPair());
  const quorum = await createSignedVerificationQuorum([a, b], { threshold: 2 });
  const policy = {
    schema: 'aml-signed-quorum-held-policy/1', prototype: true,
    artifact_type: quorum.artifact_type, artifact_hash: quorum.artifact_hash,
    trusted_key_fingerprints: [a.verifier_key_fingerprint, b.verifier_key_fingerprint],
    threshold: 2
  };
  const original = structuredClone({ quorum, policy });
  const replaying = verifySignedVerificationQuorum(quorum, { policy });
  quorum.summary.distinct_keys = 99;
  policy.artifact_hash = 'b'.repeat(64);
  const result = await replaying;
  assert.equal(result.valid, true);
  assert.equal(result.threshold_met, true);
  assert.equal(result.policy_met, true);
  assert.equal(result.input_fingerprints.quorum_sha256,
    await sha256Browser(canonicalJSONStringifyBrowser(original.quorum)));
  assert.equal(result.input_fingerprints.policy_sha256,
    await sha256Browser(canonicalJSONStringifyBrowser(original.policy)));
});

test('reusing one verifier key cannot satisfy a two-key threshold', async () => {
  const key = await createVerifierKeyPair();
  const envelopeA = await signVerificationReport(report('verifier-a'), key);
  const envelopeB = await signVerificationReport(report('verifier-b'), key);
  const quorum = await createSignedVerificationQuorum([envelopeA, envelopeB], { threshold: 2 });
  assert.equal(quorum.summary.distinct_keys, 1);
  assert.equal(quorum.summary.valid_reports, 2);
  assert.equal(quorum.summary.threshold_met, false);
  const verified = await verifySignedVerificationQuorum(JSON.parse(JSON.stringify(quorum)));
  assert.equal(verified.valid, true);
  assert.equal(verified.threshold_met, false);
  assert.equal(verified.requested_conditions_met, false);
  assert.deepEqual(verified.requested_conditions.unmet, ['threshold_met']);
});

test('verifier-held policy binds the artifact and an independently retained key allowlist', async () => {
  const a = await signVerificationReport(report('a'), await createVerifierKeyPair());
  const b = await signVerificationReport(report('b'), await createVerifierKeyPair());
  const outsider = await signVerificationReport(report('outsider'), await createVerifierKeyPair());
  const policy = {
    schema: 'aml-signed-quorum-held-policy/1', prototype: true,
    artifact_type: 'aml-witness-bundle/1', artifact_hash: 'a'.repeat(64),
    trusted_key_fingerprints: [a.verifier_key_fingerprint, b.verifier_key_fingerprint],
    threshold: 2
  };
  const supported = await verifySignedVerificationQuorum(
    JSON.parse(JSON.stringify(await createSignedVerificationQuorum([a, b], { threshold: 2 }))),
    { policy }
  );
  assert.equal(supported.valid, true);
  assert.equal(supported.threshold_met, true);
  assert.equal(supported.policy_met, true);
  assert.equal(supported.policy_evaluation.distinct_trusted_keys, 2);

  const selfSelected = await verifySignedVerificationQuorum(
    JSON.parse(JSON.stringify(await createSignedVerificationQuorum([a, outsider], { threshold: 2 }))),
    { policy }
  );
  assert.equal(selfSelected.valid, true);
  assert.equal(selfSelected.threshold_met, true);
  assert.equal(selfSelected.policy_met, false);
  assert.equal(selfSelected.requested_conditions_met, false);
  assert.deepEqual(selfSelected.requested_conditions, {
    checked: ['valid', 'threshold_met', 'policy_met'], unmet: ['policy_met']
  });
  assert.equal(selfSelected.policy_evaluation.distinct_trusted_keys, 1);

  const wrongArtifact = await verifySignedVerificationQuorum(supported.quorum, {
    policy: { ...policy, artifact_hash: 'b'.repeat(64) }
  });
  assert.equal(wrongArtifact.valid, true);
  assert.equal(wrongArtifact.threshold_met, true);
  assert.equal(wrongArtifact.policy_met, false);
  assert.equal(wrongArtifact.policy_evaluation.artifact_matches, false);

  const inflated = structuredClone(supported.quorum);
  inflated.summary.distinct_keys += 1;
  const mismatch = await verifySignedVerificationQuorum(inflated, { policy });
  assert.equal(mismatch.valid, false);
  assert.equal(mismatch.policy_met, false);

  await assert.rejects(
    () => verifySignedVerificationQuorum(supported.quorum, {
      policy: { ...policy, trusted_key_fingerprints: [a.verifier_key_fingerprint, a.verifier_key_fingerprint] }
    }), /AML_SIGNED_QUORUM_POLICY_KEYS_INVALID/
  );
  await assert.rejects(
    () => verifySignedVerificationQuorum(supported.quorum, { policy: { ...policy, threshold: 3 } }),
    /AML_SIGNED_QUORUM_POLICY_THRESHOLD_INVALID/
  );
  await assert.rejects(
    () => verifySignedVerificationQuorum(supported.quorum, { policy: { ...policy, certified: true } }),
    /AML_SIGNED_QUORUM_POLICY_INVALID/
  );
});

test('buyer-held trust groups require distinct key material across chosen groups', async () => {
  const a = await signVerificationReport(report('a'), await createVerifierKeyPair());
  const b = await signVerificationReport(report('b'), await createVerifierKeyPair());
  const c = await signVerificationReport(report('c'), await createVerifierKeyPair());
  const policy = {
    schema: 'aml-signed-quorum-held-policy/2', prototype: true,
    artifact_type: 'aml-witness-bundle/1', artifact_hash: 'a'.repeat(64),
    trusted_keys: [
      { verifier_key_fingerprint: a.verifier_key_fingerprint, trust_group: 'lab-a' },
      { verifier_key_fingerprint: b.verifier_key_fingerprint, trust_group: 'lab-a' },
      { verifier_key_fingerprint: c.verifier_key_fingerprint, trust_group: 'lab-b' }
    ],
    threshold: 2, group_threshold: 2
  };
  const sameGroupQuorum = await createSignedVerificationQuorum([a, b], { threshold: 2 });
  const sameGroup = await verifySignedVerificationQuorum(sameGroupQuorum, { policy });
  assert.equal(sameGroup.valid, true);
  assert.equal(sameGroup.threshold_met, true);
  assert.equal(sameGroup.policy_met, false);
  assert.equal(sameGroup.policy_evaluation.distinct_trusted_keys, 2);
  assert.equal(sameGroup.policy_evaluation.distinct_trust_groups, 1);

  const diverseQuorum = await createSignedVerificationQuorum([a, c], { threshold: 2 });
  const diverse = await verifySignedVerificationQuorum(diverseQuorum, { policy });
  assert.equal(diverse.policy_met, true);
  assert.equal(diverse.policy_evaluation.distinct_trust_groups, 2);
  assert.deepEqual(diverse.policy_evaluation.conflicting_key_material_fingerprints, []);

  const unmet = await verifySignedVerificationQuorum(
    await createSignedVerificationQuorum([a, c], { threshold: 3 }), { policy }
  );
  assert.equal(unmet.valid, true);
  assert.equal(unmet.threshold_met, false);
  assert.equal(unmet.policy_met, true);

  const alias = structuredClone(a);
  alias.verifier_public_key_jwk.kid = 'metadata-label-for-same-key';
  alias.verifier_key_fingerprint = await sha256Browser(alias.verifier_public_key_jwk);
  const conflictingPolicy = { ...policy, trusted_keys: [
    policy.trusted_keys[0],
    { verifier_key_fingerprint: alias.verifier_key_fingerprint, trust_group: 'lab-b' },
    policy.trusted_keys[1]
  ] };
  const aliasQuorum = await createSignedVerificationQuorum([a, alias, b], { threshold: 2 });
  const conflict = await verifySignedVerificationQuorum(aliasQuorum, { policy: conflictingPolicy });
  assert.equal(conflict.valid, true);
  assert.equal(conflict.threshold_met, true);
  assert.equal(conflict.policy_met, false);
  assert.equal(conflict.policy_evaluation.distinct_trusted_keys, 2);
  assert.equal(conflict.policy_evaluation.distinct_trust_groups, 1);
  assert.equal(conflict.policy_evaluation.conflicting_key_material_fingerprints.length, 1);

  for (const [invalid, reason] of [
    [{ ...policy, group_threshold: 3 }, /AML_SIGNED_QUORUM_POLICY_GROUP_THRESHOLD_INVALID/],
    [{ ...policy, trusted_keys: [policy.trusted_keys[0], policy.trusted_keys[0]] },
      /AML_SIGNED_QUORUM_POLICY_KEYS_INVALID/],
    [{ ...policy, trusted_keys: [{ ...policy.trusted_keys[0], trust_group: 'Lab A' }] },
      /AML_SIGNED_QUORUM_POLICY_GROUPS_INVALID/],
    [{ ...policy, trusted_keys: [{ ...policy.trusted_keys[0], certified: true }] },
      /AML_SIGNED_QUORUM_POLICY_GROUPS_INVALID/]
  ]) {
    await assert.rejects(() => verifySignedVerificationQuorum(diverseQuorum, { policy: invalid }), reason);
  }
});

test('material-pinned trust roster detects dormant aliases and wrong key material', async () => {
  const a = await signVerificationReport(report('a'), await createVerifierKeyPair());
  const b = await signVerificationReport(report('b'), await createVerifierKeyPair());
  const fingerprintA = await fingerprintVerifierPublicKey(a.verifier_public_key_jwk);
  const fingerprintB = await fingerprintVerifierPublicKey(b.verifier_public_key_jwk);
  assert.equal(fingerprintA.verifier_key_fingerprint, a.verifier_key_fingerprint);
  assert.equal(fingerprintB.verifier_key_fingerprint, b.verifier_key_fingerprint);
  const policy = {
    schema: 'aml-signed-quorum-held-policy/3', prototype: true,
    artifact_type: 'aml-witness-bundle/1', artifact_hash: 'a'.repeat(64),
    trusted_keys: [
      { ...fingerprintA, trust_group: 'lab-a' },
      { ...fingerprintB, trust_group: 'lab-b' }
    ], threshold: 2, group_threshold: 2
  };
  const quorum = await createSignedVerificationQuorum([a, b], { threshold: 2 });
  const verified = await verifySignedVerificationQuorum(quorum, { policy });
  assert.equal(verified.valid, true);
  assert.equal(verified.threshold_met, true);
  assert.equal(verified.policy_met, true);
  assert.deepEqual(verified.policy_evaluation.mismatched_key_fingerprints, []);

  const wrongPin = { ...policy, trusted_keys: [policy.trusted_keys[0],
    { ...policy.trusted_keys[1], key_material_fingerprint: '0'.repeat(64) }] };
  const mismatch = await verifySignedVerificationQuorum(quorum, { policy: wrongPin });
  assert.equal(mismatch.valid, true);
  assert.equal(mismatch.threshold_met, true);
  assert.equal(mismatch.policy_met, false);
  assert.equal(mismatch.policy_evaluation.distinct_trusted_keys, 1);
  assert.deepEqual(mismatch.policy_evaluation.mismatched_key_fingerprints, [b.verifier_key_fingerprint]);

  const c = await signVerificationReport(report('c'), await createVerifierKeyPair());
  const extraWrongPin = { ...policy, trusted_keys: [...policy.trusted_keys,
    { ...await fingerprintVerifierPublicKey(c.verifier_public_key_jwk),
      key_material_fingerprint: '0'.repeat(64), trust_group: 'lab-c' }] };
  const mixed = await verifySignedVerificationQuorum(
    await createSignedVerificationQuorum([a, b, c], { threshold: 2 }), { policy: extraWrongPin }
  );
  assert.equal(mixed.policy_evaluation.distinct_trusted_keys, 2);
  assert.equal(mixed.policy_evaluation.distinct_trust_groups, 2);
  assert.equal(mixed.policy_met, false);
  assert.deepEqual(mixed.policy_evaluation.mismatched_key_fingerprints, [c.verifier_key_fingerprint]);

  const alias = structuredClone(a.verifier_public_key_jwk);
  alias.kid = 'other-label-same-public-point';
  const aliasFingerprint = await fingerprintVerifierPublicKey(alias);
  assert.notEqual(aliasFingerprint.verifier_key_fingerprint, fingerprintA.verifier_key_fingerprint);
  assert.equal(aliasFingerprint.key_material_fingerprint, fingerprintA.key_material_fingerprint);
  await assert.rejects(() => verifySignedVerificationQuorum(quorum, { policy: {
    ...policy, trusted_keys: [policy.trusted_keys[0],
      { ...aliasFingerprint, trust_group: 'lab-b' }]
  } }), /AML_SIGNED_QUORUM_POLICY_MATERIAL_INVALID/);
  for (const invalid of [
    { ...policy, trusted_keys: [policy.trusted_keys[0],
      { ...policy.trusted_keys[1], key_material_fingerprint: 'not-a-hash' }] },
    { ...policy, trusted_keys: [policy.trusted_keys[0],
      { ...policy.trusted_keys[1], key_material_fingerprint: fingerprintA.key_material_fingerprint }] }
  ]) {
    await assert.rejects(() => verifySignedVerificationQuorum(quorum, { policy: invalid }),
      /AML_SIGNED_QUORUM_POLICY_MATERIAL_INVALID/);
  }
  await assert.rejects(() => fingerprintVerifierPublicKey({ ...a.verifier_public_key_jwk, d: 'private' }),
    /AML_SIGNED_QUORUM_PUBLIC_KEY_INVALID/);
});

test('JWK metadata aliases cannot turn one P-256 key into two endorsers', async () => {
  const envelope = await signVerificationReport(report('a'), await createVerifierKeyPair());
  const alias = structuredClone(envelope);
  alias.verifier_public_key_jwk.kid = 'a second label for the same key';
  alias.verifier_key_fingerprint = await sha256Browser(alias.verifier_public_key_jwk);
  assert.notEqual(alias.verifier_key_fingerprint, envelope.verifier_key_fingerprint);
  assert.equal((await verifySignedVerificationReport(alias)).valid, true);

  const quorum = await createSignedVerificationQuorum([envelope, alias], { threshold: 2 });
  assert.equal(quorum.summary.valid_signatures, 2);
  assert.equal(quorum.summary.distinct_keys, 1);
  assert.equal(quorum.summary.threshold_met, false);

  const policy = {
    schema: 'aml-signed-quorum-held-policy/1', prototype: true,
    artifact_type: 'aml-witness-bundle/1', artifact_hash: 'a'.repeat(64),
    trusted_key_fingerprints: [envelope.verifier_key_fingerprint, alias.verifier_key_fingerprint],
    threshold: 2
  };
  const check = await verifySignedVerificationQuorum(JSON.parse(JSON.stringify(quorum)), { policy });
  assert.equal(check.valid, true);
  assert.equal(check.threshold_met, false);
  assert.equal(check.policy_met, false);
  assert.equal(check.policy_evaluation.distinct_trusted_keys, 1);
});

test('a correctly signed invalid report is dissent and cannot satisfy the distinct-key quorum', async () => {
  const keyA = await createVerifierKeyPair();
  const keyB = await createVerifierKeyPair();
  const envelopeA1 = await signVerificationReport(report('verifier-a-1'), keyA);
  const envelopeA2 = await signVerificationReport(report('verifier-a-2'), keyA);
  const dissent = await signVerificationReport(report('verifier-b', 'a'.repeat(64), false), keyB);

  const quorum = await createSignedVerificationQuorum([envelopeA1, envelopeA2, dissent], { threshold: 2 });
  assert.equal(quorum.summary.valid_signatures, 3);
  assert.equal(quorum.summary.valid_reports, 2);
  assert.equal(quorum.summary.invalid_reports, 1);
  assert.equal(quorum.summary.distinct_keys, 1);
  assert.equal(quorum.summary.threshold_met, false);
  assert.equal(quorum.summary.unanimous, false);
  assert.ok(quorum.summary.disagreement_reasons.includes('AML_SESSION_SIGNATURE_INVALID'));
});

test('signed verification quorum rejects mixed artifact hashes', async () => {
  const keyA = await createVerifierKeyPair();
  const keyB = await createVerifierKeyPair();
  const envelopeA = await signVerificationReport(report('verifier-a', 'a'.repeat(64)), keyA);
  const envelopeB = await signVerificationReport(report('verifier-b', 'b'.repeat(64)), keyB);
  await assert.rejects(
    () => createSignedVerificationQuorum([envelopeA, envelopeB], { threshold: 2 }),
    /AML_SIGNED_QUORUM_ARTIFACT_HASH_MISMATCH/
  );
});

test('signed quorum cannot count a report without a bound artifact as an endorsement', async () => {
  const good = await signVerificationReport(report('verifier-a'), await createVerifierKeyPair());
  const unboundReport = report('verifier-b');
  unboundReport.artifact_hash = null;
  const unbound = await signVerificationReport(unboundReport, await createVerifierKeyPair());
  assert.equal((await verifySignedVerificationReport(unbound)).valid, true);
  await assert.rejects(
    () => createSignedVerificationQuorum([good, unbound], { threshold: 2 }),
    /AML_SIGNED_QUORUM_ARTIFACT_HASH_REQUIRED/
  );
});

test('signed quorum rejects truthy non-boolean verdicts even with distinct valid signatures', async () => {
  const good = await signVerificationReport(report('verifier-a'), await createVerifierKeyPair());
  const malformedReport = report('verifier-b');
  malformedReport.valid = 'false';
  const malformed = await signVerificationReport(malformedReport, await createVerifierKeyPair());
  assert.equal((await verifySignedVerificationReport(malformed)).valid, true);
  await assert.rejects(
    () => createSignedVerificationQuorum([good, malformed], { threshold: 2 }),
    /AML_SIGNED_QUORUM_REPORT_VERDICT_INVALID/
  );
});
