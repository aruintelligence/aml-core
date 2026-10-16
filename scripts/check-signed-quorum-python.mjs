// Black-box comparison of saved JS quorums against the project-authored Python verifier.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { webcrypto } from 'node:crypto';
import { sha256Browser } from '../docs/aml-browser-integrity.js';
import { createVerifierKeyPair, signVerificationReport } from '../docs/aml-signed-verification-report.js';
import { createSignedVerificationQuorum, verifySignedVerificationQuorum } from '../docs/aml-signed-verification-quorum.js';

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

async function compare(name, quorum, policy, expected) {
  const args = [python, save(`${name}-quorum.json`, quorum)];
  if (policy) args.push('--policy', save(`${name}-policy.json`, policy));
  const run = spawnSync('python3', args, {
    encoding: 'utf8', env: { ...process.env, PYTHONDONTWRITEBYTECODE: '1' }
  });
  if (run.error) throw run.error;
  assert.ok(run.stdout, `${name}: ${run.stderr}`);
  const py = JSON.parse(run.stdout);
  const js = await verifySignedVerificationQuorum(quorum, { policy });
  for (const field of ['valid', 'threshold_met', ...(policy ? ['policy_met'] : [])]) {
    assert.equal(py[field], js[field], `${name}: ${field}: ${run.stderr} ${run.stdout}`);
  }
  assert.equal(py.valid && py.threshold_met && (!policy || py.policy_met), expected, name);
  assert.equal(run.status, expected ? 0 : 2, `${name}: ${run.stderr} ${run.stdout}`);
  if (js.valid) assert.deepEqual(py.summary, js.quorum.summary, name);
  checks.push({ case: name, valid: py.valid, threshold_met: py.threshold_met,
    ...(policy ? { policy_met: py.policy_met } : {}), python_matches_js: true });
}

try {
  const fixedQuorum = JSON.parse(fs.readFileSync('independent/python/signed-quorum-vector.json', 'utf8'));
  const fixedPolicy = JSON.parse(fs.readFileSync(
    'independent/python/signed-quorum-held-policy-vector.json', 'utf8'
  ));
  await compare('published-synthetic-vector', fixedQuorum, fixedPolicy, true);
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
  const dissent = await signVerificationReport(report('dissent', false), keyB);
  await compare('authenticated-dissent',
    await createSignedVerificationQuorum([a, dissent], { threshold: 2 }), policy, false);
  const invalidSignature = structuredClone(b);
  invalidSignature.signature = `${invalidSignature.signature[0] === 'A' ? 'B' : 'A'}${invalidSignature.signature.slice(1)}`;
  await compare('invalid-signature-counted-as-rejection',
    await createSignedVerificationQuorum([a, invalidSignature], { threshold: 2 }), policy, false);

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

  console.log(JSON.stringify({
    protocol: 'aml-signed-quorum-python-cross-runtime/1',
    passed: true, cases: checks,
    additional_rejections: ['duplicate_json_key', 'fractional_canonical_value',
      'malformed_signature', 'invalid_held_policy'],
    claim_boundary: 'Project-authored Python and JavaScript implementations agree on these saved quorum and held-policy cases. This is not an external witness, signer identity, or independent certification.'
  }, null, 2));
} finally {
  fs.rmSync(directory, { recursive: true, force: true });
}
