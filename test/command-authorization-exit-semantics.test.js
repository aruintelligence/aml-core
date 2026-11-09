// Exit-status contract for verifier and validator commands: exit 0 only when
// the complete authorization decision is explicitly true. A consistent
// (`valid: true`) but unauthorized result exits 3; missing trust inputs are
// not authorization; --diagnostic-only exits 0 for a consistent result but
// reports authorized:false and NOT AN AUTHORIZATION DECISION.
import test from 'node:test';
import assert from 'node:assert/strict';
import crypto, { webcrypto } from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { createGovernanceStreamTranscript } from '../protocol/governanceTranscript.js';
import { createGovernanceDisclosure } from '../protocol/governanceDisclosure.js';
import { signGovernanceDisclosureCommitment } from '../protocol/governanceDisclosureSignature.js';
import { signGovernanceStreamTranscript } from '../protocol/governanceTranscriptSignature.js';
import { RELEASE_AUTHORIZATION_PROFILE_PROTOCOL, releaseAuthorizationProfileFingerprint }
  from '../tooling/releaseAuthorizationProfile.js';
import { AML_SEMANTIC_RELEASE_PREDICATE_V1 } from '../compiler/inTotoSemanticRelease.js';
import { buildExternalVerifierKit } from '../scripts/build-external-verifier-kit.mjs';
import { sealBrowserReceipt } from '../docs/aml-browser-integrity.js';
import { createBrowserEvidence } from '../docs/aml-browser-evidence.js';
import { createVerificationChallenge } from '../docs/aml-verification-challenge.js';
import { createSessionAttestation } from '../docs/aml-session-attestation.js';
import { createWitnessBundle } from '../docs/aml-witness-bundle.js';
import { commandAuthorizationDecision, commandOutcome, trustedCommandClock, withCommandAuthorization,
  AML_EXIT_NOT_AUTHORIZED, AML_NOT_AN_AUTHORIZATION_DECISION } from '../runtime/commandAuthorization.js';

if (!globalThis.crypto?.subtle) globalThis.crypto = webcrypto;
const NOT_AUTH = AML_NOT_AN_AUTHORIZATION_DECISION;

function tmp(t) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'aml-exit-semantics-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  return (name, value) => {
    const file = path.join(dir, name);
    fs.writeFileSync(file, typeof value === 'string' ? value : JSON.stringify(value, null, 2));
    return file;
  };
}

function run(binary, args, env = {}) {
  const result = spawnSync(binary, args, { encoding: 'utf8', env: { ...process.env, PYTHONDONTWRITEBYTECODE: '1', ...env } });
  let json = null;
  try { json = JSON.parse(result.stdout); } catch { /* non-JSON output */ }
  return { status: result.status, json, stdout: result.stdout, stderr: result.stderr };
}
const node = (script, args, env) => run(process.execPath, [script, ...args], env);

// Every decision-mode run with valid:true but no authorization must exit 3,
// expose `authorized: false` and the denial reasons, and never exit 0.
function assertNotAuthorized(r, reason, label) {
  assert.equal(r.status, AML_EXIT_NOT_AUTHORIZED, `${label}: ${r.stderr} ${r.stdout}`);
  assert.equal(r.json.valid, true, label);
  assert.equal(r.json.authorized, false, label);
  assert.equal(r.json.authorization.authorized, false, label);
  if (reason) assert.ok(r.json.authorization.reasons.includes(reason), `${label}: ${r.json.authorization.reasons}`);
  assert.ok(Array.isArray(r.json.remaining_trust_assumptions), label);
}
function assertAuthorized(r, label) {
  assert.equal(r.status, 0, `${label}: ${r.stderr} ${r.stdout}`);
  assert.equal(r.json.valid, true, label);
  assert.equal(r.json.authorized, true, label);
  assert.equal(r.json.authorization.authorized, true, label);
  assert.deepEqual(r.json.authorization.reasons, ['AML_AUTHZ_ALLOW'], label);
}
function assertDiagnostic(r, label) {
  assert.equal(r.status, 0, `${label}: ${r.stderr} ${r.stdout}`);
  assert.equal(r.json.authorized, false, label);
  assert.equal(r.json.diagnostic_only, true, label);
  assert.equal(r.json.decision_use, NOT_AUTH, label);
}

const messages = fs.readFileSync('conformance/governance-stream/mixed.ndjson', 'utf8')
  .split(/\r?\n/).map(line => line.trim()).filter(Boolean).map(line => JSON.parse(line));

test('authorization decision fails closed on missing, unknown, non-boolean, inherited and throwing conditions', () => {
  const required = ['a', 'b'];
  const denials = { a: 'AML_AUTHZ_A', b: 'AML_AUTHZ_B' };
  assert.equal(commandAuthorizationDecision({ a: true, b: true }, required, denials).authorized, true);
  for (const [label, conditions] of [
    ['missing', { a: true }], ['false', { a: true, b: false }], ['string', { a: true, b: 'true' }],
    ['number', { a: true, b: 1 }], ['unknown', { a: true, b: true, c: true }],
    ['inherited', Object.assign(Object.create({ b: true }), { a: true })],
    ['null', null], ['array', [true, true]],
    ['throwing', new Proxy({}, { ownKeys() { throw new Error('x'); }, getOwnPropertyDescriptor() { throw new Error('x'); } })]
  ]) {
    const decision = commandAuthorizationDecision(conditions, required, denials);
    assert.equal(decision.authorized, false, label);
    assert.equal(decision.decision, 'deny', label);
  }
  assert.equal(commandAuthorizationDecision({ a: true }, [], denials).authorized, false, 'empty required list');
  // commandOutcome: valid alone never exits 0; inconsistent authorized flags never exit 0.
  const valid = { valid: true };
  assert.equal(commandOutcome(valid).exitCode, 3);
  assert.equal(commandOutcome({ valid: true, authorized: true }).exitCode, 3, 'authorized without decision object');
  assert.equal(commandOutcome({ valid: true, authorized: true, authorization: { authorized: 'true' } }).exitCode, 3);
  assert.equal(commandOutcome({ valid: false, authorized: true, authorization: { authorized: true } }, { invalidCode: 2 }).exitCode, 2);
  const allowed = withCommandAuthorization({ valid: true }, commandAuthorizationDecision({ a: true, b: true }, required, denials));
  assert.equal(commandOutcome(allowed).exitCode, 0);
  const diag = commandOutcome(allowed, { diagnosticOnly: true });
  assert.equal(diag.exitCode, 0);
  assert.equal(diag.output.authorized, false);
  assert.equal(diag.output.decision_use, NOT_AUTH);
  assert.equal(commandOutcome({ valid: false }, { diagnosticOnly: true, invalidCode: 1 }).exitCode, 1);
  // Own clock only: a caller time counts only within the skew bound.
  const now = Date.now();
  assert.equal(trustedCommandClock(undefined, now), true);
  assert.equal(trustedCommandClock(new Date(now + 500).toISOString(), now), true);
  assert.equal(trustedCommandClock(new Date(now - 60_000).toISOString(), now), false);
  assert.equal(trustedCommandClock(new Date(now + 60_000).toISOString(), now), false);
  assert.equal(trustedCommandClock('not a time', now), false);
});

test('governance disclosure verify: authorized only with a pinned Merkle root', t => {
  const save = tmp(t);
  const disclosure = createGovernanceDisclosure(createGovernanceStreamTranscript(messages), [1, 4]);
  const file = save('disclosure.json', disclosure);
  const bin = 'bin/aml-governance-disclosure-verify.js';
  const plain = node(bin, [file]);
  assertNotAuthorized(plain, 'AML_AUTHZ_MERKLE_ROOT_NOT_PINNED', 'no pin');
  const root = plain.json.disclosure_merkle_root_sha256;
  assert.match(root, /^[a-f0-9]{64}$/);
  assertAuthorized(node(bin, [file, '--expected-merkle-root', root]), 'pinned');
  assert.notEqual(node(bin, [file, '--expected-merkle-root', '0'.repeat(64)]).status, 0, 'wrong pin');
  assert.notEqual(node(bin, [file, '--expected-merkle-root', root.toUpperCase()]).status, 0, 'non-canonical pin');
  assertDiagnostic(node(bin, [file, '--diagnostic-only']), 'diagnostic');
  const tampered = save('tampered.json', { ...disclosure, disclosure_merkle_root_sha256: '1'.repeat(64) });
  assert.equal(node(bin, [tampered, '--expected-merkle-root', '1'.repeat(64)]).status, 2, 'tampered');
  assert.equal(node(bin, [tampered, '--diagnostic-only']).status, 2, 'tampered diagnostic');
});

test('signed governance disclosure verify: authorized only with a trusted key and pinned scope', t => {
  const save = tmp(t);
  const disclosure = createGovernanceDisclosure(createGovernanceStreamTranscript(messages), [1, 4]);
  const { privateKey } = crypto.generateKeyPairSync('ed25519');
  const signed = signGovernanceDisclosureCommitment(disclosure,
    privateKey.export({ type: 'pkcs8', format: 'pem' }).toString(), { signer: 'synthetic-test-witness' });
  const fingerprint = signed.signature.public_key_fingerprint_sha256;
  const d = save('disclosure.json', disclosure);
  const s = save('signed.json', signed);
  const bin = 'bin/aml-governance-disclosure-signed-verify.js';
  const scope = signed.signature.scope;
  assertNotAuthorized(node(bin, [d, s]), 'AML_AUTHZ_KEY_NOT_TRUSTED', 'no trust inputs');
  assertNotAuthorized(node(bin, [d, s, '--trusted-fingerprints', fingerprint]), 'AML_AUTHZ_SCOPE_NOT_PINNED', 'no scope');
  assertNotAuthorized(node(bin, [d, s, '--required-scope', scope]), 'AML_AUTHZ_KEY_NOT_TRUSTED', 'no key');
  assertAuthorized(node(bin, [d, s, '--trusted-fingerprints', fingerprint, '--required-scope', scope]), 'trusted and scoped');
  assert.notEqual(node(bin, [d, s, '--trusted-fingerprints', fingerprint, '--revoked-fingerprints', fingerprint,
    '--required-scope', scope]).status, 0, 'revoked');
  assertDiagnostic(node(bin, [d, s, '--diagnostic-only']), 'diagnostic');
});

test('release profile: validate never authorizes; verify needs the pinned fingerprint', t => {
  const save = tmp(t);
  const profile = {
    protocol: RELEASE_AUTHORIZATION_PROFILE_PROTOCOL, profile_id: 'synthetic-release-v1',
    repository: 'example/app', signer_workflow: 'example/app/.github/workflows/release.yml',
    allow_self_hosted: false, predicate_type: AML_SEMANTIC_RELEASE_PREDICATE_V1,
    required_layers: { github_attestation: true, semantic_release_proof: true, release_key_trust: true, semantic_release_quorum: true },
    release_key_policy_sha256: 'a'.repeat(64), quorum_policy_sha256: 'b'.repeat(64)
  };
  const file = save('profile.json', profile);
  const bin = 'bin/aml-release-profile.js';
  assertNotAuthorized(node(bin, ['validate', file]), 'AML_AUTHZ_PROFILE_FINGERPRINT_NOT_PINNED', 'validate');
  assertDiagnostic(node(bin, ['validate', file, '--diagnostic-only']), 'validate diagnostic');
  const fingerprint = releaseAuthorizationProfileFingerprint(profile);
  assertAuthorized(node(bin, ['verify', file, fingerprint]), 'verify pinned');
  assert.notEqual(node(bin, ['verify', file, 'c'.repeat(64)]).status, 0, 'verify wrong pin');
  const invalid = save('invalid.json', { ...profile, allow_self_hosted: 'yes' });
  assert.equal(node(bin, ['validate', invalid]).status, 1, 'invalid profile');
  assert.equal(node(bin, ['validate']).status, 2, 'usage');
});

test('governance transcript CLIs: unsigned never authorizes; signed needs trusted key and pinned key id', t => {
  const save = tmp(t);
  const transcript = createGovernanceStreamTranscript(messages);
  const unsigned = save('transcript.json', transcript);
  assertNotAuthorized(node('bin/aml-governance-transcript-verify.js', [unsigned]), 'AML_AUTHZ_TRANSCRIPT_UNAUTHENTICATED', 'unsigned');
  assertDiagnostic(node('bin/aml-governance-transcript-verify.js', [unsigned, '--diagnostic-only']), 'unsigned diagnostic');
  const pair = crypto.generateKeyPairSync('ed25519', {
    publicKeyEncoding: { type: 'spki', format: 'pem' }, privateKeyEncoding: { type: 'pkcs8', format: 'pem' } });
  const signed = signGovernanceStreamTranscript(transcript, pair.privateKey, {
    key_id: 'synthetic-key-1', signer: 'synthetic-test', signed_at: new Date().toISOString() });
  const file = save('signed-transcript.json', signed);
  const fingerprint = signed.signature.public_key_fingerprint_sha256;
  const bin = 'bin/aml-governance-transcript-signature-verify.js';
  assertNotAuthorized(node(bin, [file]), 'AML_AUTHZ_KEY_NOT_TRUSTED', 'no trust');
  assertNotAuthorized(node(bin, [file, '--trusted-fingerprint', fingerprint]), 'AML_AUTHZ_KEY_ID_NOT_PINNED', 'no key id');
  assertAuthorized(node(bin, [file, '--trusted-fingerprint', fingerprint, '--expected-key-id', 'synthetic-key-1']), 'trusted');
  assert.notEqual(node(bin, [file, '--trusted-fingerprint', fingerprint, '--expected-key-id', 'other']).status, 0, 'wrong key id');
  assertDiagnostic(node(bin, [file, '--diagnostic-only']), 'signed diagnostic');
});

test('external verifier kit check: authorized only with a pinned root', t => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'aml-exit-kit-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const kit = path.join(dir, 'kit');
  const built = buildExternalVerifierKit(kit);
  const script = 'scripts/check-external-verifier-kit.mjs';
  assertNotAuthorized(node(script, [kit]), 'AML_AUTHZ_KIT_ROOT_NOT_PINNED', 'no pin');
  assertAuthorized(node(script, [kit, '--expected-root-sha256', built.manifest.root_sha256]), 'pinned');
  assert.notEqual(node(script, [kit, '--expected-root-sha256', 'd'.repeat(64)]).status, 0, 'wrong pin');
  assertDiagnostic(node(script, ['--diagnostic-only', kit]), 'diagnostic');
  fs.appendFileSync(path.join(kit, 'conformance/verifier-challenge.json'), ' ');
  assert.equal(node(script, [kit, '--expected-root-sha256', built.manifest.root_sha256]).status, 1, 'tampered');
});

test('witness record validator and gate never authorize; the action output says so', t => {
  const save = tmp(t);
  const challengeSha256 = crypto.createHash('sha256').update(fs.readFileSync('conformance/verifier-challenge.json')).digest('hex');
  const record = {
    schema: 'aml-witness-record/1', witness_id: 'synthetic-outside-verifier-001', observed_at: '2026-09-09T07:15:00Z',
    source_url: 'https://github.com/example-labs/aml-verifier', artifact_type: 'aml-external-verifier-challenge/1',
    artifact_hash: challengeSha256, verifier: 'example-go-verifier', runtime: 'go1.24', result: 'PASS',
    external_to_aml_core: true, summary: 'Synthetic black-box verifier record.',
    report_url: 'https://github.com/example-labs/aml-verifier/actions/runs/123', notes: []
  };
  const example = save('record.json', record);
  assertNotAuthorized(node('scripts/validate-witness-record.mjs', [example]), 'AML_AUTHZ_HUMAN_REVIEW_REQUIRED', 'validator');
  assertDiagnostic(node('scripts/validate-witness-record.mjs', [example, '--diagnostic-only']), 'validator diagnostic');
  const out = save('github-output.txt', '');
  assertNotAuthorized(node('scripts/witness-record-gate.mjs', [example], { GITHUB_OUTPUT: out }), 'AML_AUTHZ_HUMAN_REVIEW_REQUIRED', 'gate');
  const lines = fs.readFileSync(out, 'utf8');
  assert.match(lines, /^valid=true$/m);
  assert.match(lines, /^authorized=false$/m);
  assert.match(lines, /^decision-use=NOT AN AUTHORIZATION DECISION$/m);
  assertDiagnostic(node('scripts/witness-record-gate.mjs', ['--diagnostic-only', example]), 'gate diagnostic');
  const broken = save('broken.json', { ...record, artifact_hash: '0'.repeat(64) });
  assert.equal(node('scripts/witness-record-gate.mjs', [broken]).status, 1, 'invalid record');
  assert.equal(node('scripts/witness-record-gate.mjs', [broken, '--diagnostic-only']).status, 1, 'invalid diagnostic');
  const action = fs.readFileSync('actions/witness-record/action.yml', 'utf8');
  assert.match(action, /witness-record-gate\.mjs" --diagnostic-only/);
  assert.match(action, /NOT AN AUTHORIZATION DECISION/);
});

async function freshWitness() {
  const receipt = await sealBrowserReceipt({ schema: 'aml-dom-receipt/1', decisions: [] });
  const evidence = await createBrowserEvidence(receipt, { url: 'https://example.test/' });
  const challenge = createVerificationChallenge({ ttl_ms: 120000 });
  const attestation = await createSessionAttestation({ evidence, challenge });
  await new Promise(resolve => setTimeout(resolve, 10));
  return { bundle: await createWitnessBundle({ evidence, challenge, attestation }), challenge };
}

test('Python witness verifier: authorized only with held challenge and its own clock', async t => {
  const save = tmp(t);
  const { bundle, challenge } = await freshWitness();
  const b = save('bundle.json', bundle);
  const c = save('challenge.json', challenge);
  const py = ['independent/python/verify_witness.py'];
  assertAuthorized(run('python3', [...py, b, '--challenge', c]), 'held challenge, own clock');
  assertNotAuthorized(run('python3', [...py, b]), 'AML_AUTHZ_HELD_CHALLENGE_NOT_MATCHED', 'no challenge');
  const callerTime = new Date(Date.now() + 30_000).toISOString();
  assertNotAuthorized(run('python3', [...py, b, '--challenge', c, '--now', callerTime]), 'AML_AUTHZ_CALLER_CLOCK_UNTRUSTED', 'caller clock');
  assertNotAuthorized(run('python3', [...py, 'independent/python/witness-vector.json', '--now', '2030-01-01T00:05:00Z']),
    null, 'published vector, caller clock');
  assertDiagnostic(run('python3', [...py, '--diagnostic-only', 'independent/python/witness-vector.json', '--now', '2030-01-01T00:05:00Z']), 'diagnostic');
  const tampered = save('tampered.json', { ...bundle, created_at: '2001-01-01T00:00:00.000Z' });
  assert.equal(run('python3', [...py, tampered, '--challenge', c]).status, 1, 'tampered');
  assert.equal(run('python3', [...py, '--diagnostic-only', tampered]).status, 1, 'tampered diagnostic');
});

test('Go witness verifier never authorizes; diagnostic mode is labelled', { skip: spawnSync('go', ['version']).status !== 0 && 'go toolchain not installed' }, t => {
  const go = ['independent/go/verify.sh'];
  const vector = path.resolve('independent/python/witness-vector.json');
  const plain = run('bash', [...go, '--now', '2030-01-01T00:05:00Z', vector]);
  assertNotAuthorized(plain, 'AML_AUTHZ_HELD_CHALLENGE_UNSUPPORTED', 'go');
  assert.ok(plain.json.authorization.reasons.includes('AML_AUTHZ_CALLER_CLOCK_UNTRUSTED'));
  assertDiagnostic(run('bash', [...go, '--diagnostic-only', '--now', '2030-01-01T00:05:00Z', vector]), 'go diagnostic');
  const save = tmp(t);
  const tampered = save('tampered.json', { ...JSON.parse(fs.readFileSync(vector, 'utf8')), created_at: '2001-01-01T00:00:00.000Z' });
  assert.equal(run('bash', [...go, '--now', '2030-01-01T00:05:00Z', tampered]).status, 1, 'go tampered');
  assert.equal(run('bash', [...go, '--diagnostic-only', '--now', '2030-01-01T00:05:00Z', tampered]).status, 1, 'go tampered diagnostic');
});

test('signed quorum CLI: requested conditions met is exit 3; only a held policy decision exits 0', t => {
  const save = tmp(t);
  const quorum = 'independent/python/signed-quorum-vector.json';
  const policy = 'independent/python/signed-quorum-held-policy-vector.json';
  for (const [binary, args] of [
    [process.execPath, ['bin/aml.js', 'verify-signed-quorum']],
    ['python3', ['independent/python/verify_signed_quorum.py']]
  ]) {
    const label = path.basename(args[0]);
    const met = run(binary, [...args, quorum]);
    assert.equal(met.status, 3, `${label}: ${met.stderr}`);
    assert.equal(met.json.requested_conditions_met, true);
    assert.equal(met.json.authorized, false);
    const decision = run(binary, [...args, quorum, '--decision-only']);
    assert.equal(decision.status, 3, label);
    assert.equal(decision.json.authorized, false, label);
    const held = run(binary, [...args, quorum, '--policy', policy]);
    assert.equal(held.status, 0, `${label}: ${held.stderr}`);
    assert.equal(held.json.authorized, true, label);
    const diag = run(binary, [...args, quorum, '--diagnostic-only']);
    assert.equal(diag.status, 0, label);
    assert.equal(diag.json.authorized, false, label);
    assert.equal(diag.json.decision_use, NOT_AUTH, label);
    const broken = save(`${label}-broken.json`, '{');
    assert.equal(run(binary, [...args, broken]).status, 1, label);
  }
});
