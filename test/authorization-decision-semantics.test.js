// Project rule: for any authorization API that exposes `valid`, `valid` alone
// is never permission to execute. `valid` keeps its consistency-only meaning;
// `authorized` is the explicit, fail-closed decision. These tests cover the
// two residuals left open at a3e78ab: the signed quorum (a substituted witness
// leaves `valid` true) and the witness bundle library (`valid` is internal
// consistency; HTTP callers may supply `now`). Synthetic fixtures only.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawn, spawnSync } from 'node:child_process';
import { once } from 'node:events';
import { pathToFileURL } from 'node:url';
import { sealBrowserReceipt } from '../docs/aml-browser-integrity.js';
import { createBrowserEvidence } from '../docs/aml-browser-evidence.js';
import { createVerificationChallenge } from '../docs/aml-verification-challenge.js';
import { createSessionAttestation, resetAMLSessionKey } from '../docs/aml-session-attestation.js';
import { createWitnessBundle, verifyWitnessBundle, witnessAuthorizationDecision,
  WITNESS_AUTHORIZATION_CLOCK_SKEW_MS } from '../docs/aml-witness-bundle.js';
import { witnessVerificationReport } from '../docs/aml-verification-report.js';
import { createVerifierKeyPair, signVerificationReport } from '../docs/aml-signed-verification-report.js';
import { createSignedVerificationQuorum, verifySignedVerificationQuorum,
  signedQuorumAuthorizationDecision } from '../docs/aml-signed-verification-quorum.js';

const repo = process.cwd();

async function makeBundle({ ttl_ms = 120000 } = {}) {
  resetAMLSessionKey();
  const receipt = await sealBrowserReceipt({ schema: 'aml-dom-receipt/1', prototype: true, revision: 1,
    reason: 'synthetic-authz-fixture', url: 'https://relying-party.example.test/',
    generated_at: new Date(Date.now() - 1000).toISOString(),
    totals: { evaluated: 0, allowed: 0, suppressed: 0, errors: 0 }, decisions: [] });
  const evidence = await createBrowserEvidence(receipt, { url: 'https://relying-party.example.test/' });
  const challenge = createVerificationChallenge({ ttl_ms });
  const attestation = await createSessionAttestation({ evidence, challenge });
  await new Promise(resolve => setTimeout(resolve, 2));
  return { bundle: await createWitnessBundle({ evidence, challenge, attestation }), challenge };
}

async function makeQuorum() {
  const { bundle, challenge } = await makeBundle();
  const check = await verifyWitnessBundle(bundle, { expectedChallenge: challenge });
  const keys = [await createVerifierKeyPair(), await createVerifierKeyPair()];
  const reports = [];
  for (const [index, key] of keys.entries()) {
    reports.push(await signVerificationReport(
      witnessVerificationReport(bundle, check, { verifier: `synthetic-${index}` }), key));
  }
  const quorum = await createSignedVerificationQuorum(reports, { threshold: 2 });
  const policy = { schema: 'aml-signed-quorum-held-policy/1', prototype: true,
    artifact_type: quorum.artifact_type, artifact_hash: quorum.artifact_hash,
    trusted_key_fingerprints: reports.map(r => r.verifier_key_fingerprint), threshold: 2 };
  return { bundle, challenge, quorum, policy };
}

test('decision helpers fail closed on missing, unknown, non-boolean or hostile conditions', () => {
  const witnessAll = { bundle_valid: true, verifier_held_challenge: true, trusted_clock: true };
  const quorumAll = { valid: true, threshold_met: true, requested_conditions_met: true,
    held_policy_met: true, witness_requirement_met: true };
  for (const [decide, all] of [[witnessAuthorizationDecision, witnessAll],
    [signedQuorumAuthorizationDecision, quorumAll]]) {
    assert.equal(decide(all).authorized, true, 'positive control');
    assert.equal(decide(all).decision, 'allow');
    for (const bad of [undefined, null, [], 'true', 1, true]) {
      assert.equal(decide(bad).authorized, false, String(bad));
    }
    for (const name of Object.keys(all)) {
      const missing = { ...all }; delete missing[name];
      assert.equal(decide(missing).authorized, false, `missing ${name}`);
      for (const value of ['true', 1, {}, [], null, undefined, false]) {
        const result = decide({ ...all, [name]: value });
        assert.equal(result.authorized, false, `${name}=${JSON.stringify(value)}`);
        assert.equal(result.decision, 'deny');
        assert.ok(result.reasons.length > 0 && !result.reasons.includes('AML_AUTHZ_ALLOW'));
      }
    }
    const unknown = decide({ ...all, valid_only: true, extra: true });
    assert.equal(unknown.authorized, false);
    assert.ok(unknown.reasons.includes('AML_AUTHZ_UNKNOWN_CONDITION'));
    const inherited = decide(Object.create(all));
    assert.equal(inherited.authorized, false, 'inherited conditions are not own conditions');
    const hostile = new Proxy({}, { ownKeys() { throw new Error('boom'); },
      getOwnPropertyDescriptor() { throw new Error('boom'); }, get() { throw new Error('boom'); } });
    assert.deepEqual(decide(hostile).reasons, ['AML_AUTHZ_EVALUATION_ERROR']);
  }
});

test('witness bundle: valid=true without a retained challenge is never authorized', async () => {
  const { bundle, challenge } = await makeBundle();
  const unheld = await verifyWitnessBundle(bundle);
  assert.equal(unheld.valid, true, 'consistency meaning unchanged');
  assert.equal(unheld.verified, false);
  assert.equal(unheld.authorized, false);
  assert.deepEqual(unheld.authorization.reasons, ['AML_AUTHZ_HELD_CHALLENGE_NOT_MATCHED']);
  const substituted = await verifyWitnessBundle(bundle, { expectedChallenge: createVerificationChallenge({ ttl_ms: 60000 }) });
  assert.equal(substituted.authorized, false);
  const matched = await verifyWitnessBundle(bundle, { expectedChallenge: challenge });
  assert.equal(matched.authorized, true, 'positive control: retained challenge on the verifier clock');
  assert.deepEqual(matched.authorization.reasons, ['AML_AUTHZ_ALLOW']);
  const outer = await verifyWitnessBundle(bundle, { expectedChallenge: challenge, now: Date.now() });
  assert.equal(outer.authorized, true, 'an outer verifier passing its own just-read clock stays authorized');
});

test('witness bundle: a caller-supplied future or stale clock verifies but never authorizes', async () => {
  const { bundle, challenge } = await makeBundle();
  const future = Date.now() + 60000;
  const ahead = await verifyWitnessBundle(bundle, { expectedChallenge: challenge, now: future });
  assert.equal(ahead.verified, true, 'still inside the challenge lifetime on the caller clock');
  assert.equal(ahead.authorized, false);
  assert.deepEqual(ahead.authorization.reasons, ['AML_AUTHZ_CALLER_CLOCK_UNTRUSTED']);
  const justOutside = await verifyWitnessBundle(bundle, { expectedChallenge: challenge,
    now: Date.now() + WITNESS_AUTHORIZATION_CLOCK_SKEW_MS + 1500 });
  assert.equal(justOutside.authorized, false, 'skew bound is enforced');
  for (const now of ['2030-01-01T00:00:00.000Z', NaN, Infinity, null, undefined, {}]) {
    const result = await verifyWitnessBundle(bundle, { expectedChallenge: challenge, now });
    assert.equal(result.authorized, false, `now=${String(now)}`);
  }

  const short = await makeBundle({ ttl_ms: 1200 });
  await new Promise(resolve => setTimeout(resolve, 1500));
  const local = await verifyWitnessBundle(short.bundle, { expectedChallenge: short.challenge });
  assert.equal(local.valid, false, 'expired on the verifier clock');
  const stale = await verifyWitnessBundle(short.bundle, { expectedChallenge: short.challenge,
    now: Date.parse(short.bundle.created_at) });
  assert.equal(stale.verified, true, 'a stale caller clock makes the expired challenge look fresh');
  assert.equal(stale.authorized, false, 'but never authorizes');
  assert.ok(stale.authorization.reasons.includes('AML_AUTHZ_CALLER_CLOCK_UNTRUSTED'));
});

test('signed quorum: valid=true with a substituted witness or without a held policy is not authorized', async () => {
  const { bundle, challenge, quorum, policy } = await makeQuorum();
  const held = createVerificationChallenge({ ttl_ms: 120000 });
  const substituted = await verifySignedVerificationQuorum(quorum, { policy, witnessBundle: bundle, expectedChallenge: held });
  assert.equal(substituted.valid, true, 'preserved counterexample: valid alone misleads');
  assert.equal(substituted.threshold_met, true);
  assert.equal(substituted.authorized, false);
  assert.ok(substituted.authorization.reasons.includes('AML_AUTHZ_WITNESS_REQUIREMENT_UNMET'));

  const noPolicy = await verifySignedVerificationQuorum(quorum);
  assert.equal(noPolicy.requested_conditions_met, true, 'self-generated keys meet key-distinct conditions');
  assert.equal(noPolicy.authorized, false, 'no relying-party policy: never authorized');
  assert.deepEqual(noPolicy.authorization.reasons, ['AML_AUTHZ_HELD_POLICY_REQUIRED_AND_MET']);

  const noPolicyWitness = await verifySignedVerificationQuorum(quorum, { witnessBundle: bundle, expectedChallenge: challenge });
  assert.equal(noPolicyWitness.requested_conditions_met, true);
  assert.equal(noPolicyWitness.authorized, false);

  const wrongPolicy = await verifySignedVerificationQuorum(quorum, {
    policy: { ...policy, trusted_key_fingerprints: [policy.trusted_key_fingerprints[0], 'f'.repeat(64)] } });
  assert.equal(wrongPolicy.valid, true);
  assert.equal(wrongPolicy.authorized, false);

  const accepted = await verifySignedVerificationQuorum(quorum, { policy, witnessBundle: bundle, expectedChallenge: challenge });
  assert.equal(accepted.authorized, true, 'positive control: held policy and retained challenge');
  assert.equal(accepted.witness_evaluation.local_bundle_authorized, true);
  assert.equal((await verifySignedVerificationQuorum(quorum, { policy })).authorized, true,
    'a v1 policy that requires no witness is authorized on the policy alone');
});

// Dynamic injection: replace verifyWitnessBundle for every importer with a
// stub that returns valid=true (and verified=true) while the explicit decision
// is missing, false or non-boolean. Each execution caller must refuse.
function injectionHooks(t) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'aml-authz-inject-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const real = pathToFileURL(path.join(repo, 'docs/aml-witness-bundle.js')).href;
  fs.writeFileSync(path.join(dir, 'stub.mjs'), `export * from ${JSON.stringify(`${real}?real`)};
export async function verifyWitnessBundle(bundle, options = {}) {
  return { ...structuredClone(JSON.parse(process.env.AML_AUTHZ_INJECT)),
    session_key_fingerprint: bundle?.attestation?.session_key_fingerprint,
    challenge_expires_at: bundle?.challenge?.expires_at, evidence_hash: bundle?.evidence?.integrity?.value };
}\n`);
  fs.writeFileSync(path.join(dir, 'hooks.mjs'), `const stub = ${JSON.stringify(pathToFileURL(path.join(dir, 'stub.mjs')).href)};
export async function resolve(specifier, context, next) {
  const resolved = await next(specifier, context);
  if (resolved.url === ${JSON.stringify(real)} && context.parentURL !== stub) return { url: stub, shortCircuit: true };
  return resolved;
}\n`);
  fs.writeFileSync(path.join(dir, 'register.mjs'), `import { register } from 'node:module';
register(${JSON.stringify(pathToFileURL(path.join(dir, 'hooks.mjs')).href)});\n`);
  const write = (name, value) => { const file = path.join(dir, name); fs.writeFileSync(file, JSON.stringify(value)); return file; };
  return { dir, register: path.join(dir, 'register.mjs'), write };
}

const injected = (extra) => ({ valid: true, verified: true, reason: 'AML_WITNESS_BUNDLE_VALID',
  checks: { bundle_integrity: true, receipt_integrity: true, evidence_integrity: true, challenge_freshness: true,
    challenge_binding: true, session_signature: true, verifier_held_challenge: true },
  evaluated_at: null, freshness_clock_source: 'local_system', ...extra });
const NEGATIVE = { 'authorized missing': {}, 'authorized false': { authorized: false },
  'authorized "true"': { authorized: 'true' }, 'authorized 1': { authorized: 1 } };

test('injected valid=true without authorized: CLI, HTTP, quorum and worker callers all refuse', async t => {
  const { dir, register, write } = injectionHooks(t);
  const { bundle, challenge, quorum, policy } = await makeQuorum();
  const b = write('bundle.json', bundle), c = write('challenge.json', challenge);
  const cases = [...Object.entries(NEGATIVE).map(([name, extra]) => [name, extra, false]),
    ['positive control', { authorized: true }, true]];
  const child = fs.readFileSync(path.join(dir, 'register.mjs'), 'utf8') && path.join(dir, 'child.mjs');
  fs.writeFileSync(child, `
import { verifySignedVerificationQuorum } from ${JSON.stringify(pathToFileURL(path.join(repo, 'docs/aml-signed-verification-quorum.js')).href)};
const [quorum, policy, bundle, challenge] = ['q', 'p', 'b', 'c'].map(k => JSON.parse(process.env['AML_IN_' + k]));
const quorumResult = await verifySignedVerificationQuorum(quorum, { policy, witnessBundle: bundle, expectedChallenge: challenge });
let posted;
globalThis.self = { addEventListener(type, fn) { globalThis.handler = fn; }, postMessage(message) { posted = message; } };
await import(${JSON.stringify(pathToFileURL(path.join(repo, 'docs/aml-verifier-worker.js')).href)});
await globalThis.handler({ data: { id: 1, bundle, expectedChallenge: challenge } });
console.log(JSON.stringify({ witness_met: quorumResult.witness_met, authorized: quorumResult.authorized,
  valid: quorumResult.valid, worker_authorized: posted?.authorized, worker_report_valid: posted?.report?.valid }));
`);
  const server = path.join(dir, 'server.mjs');
  fs.writeFileSync(server, `
import { createAmlHttpServer } from ${JSON.stringify(pathToFileURL(path.join(repo, 'index.js')).href)};
const server = createAmlHttpServer();
server.listen(0, '127.0.0.1', () => console.log(server.address().port));
`);
  for (const [name, extra, expected] of cases) {
    const env = { ...process.env, AML_AUTHZ_INJECT: JSON.stringify(injected(extra)) };
    const cli = spawnSync(process.execPath, ['--import', register, 'bin/aml.js', 'verify-witness', b, c],
      { cwd: repo, encoding: 'utf8', env });
    assert.equal(cli.status, expected ? 0 : 2, `CLI ${name}: ${cli.stderr}`);
    assert.equal(JSON.parse(cli.stdout).valid, true, `CLI ${name}: injection engaged`);

    const libs = spawnSync(process.execPath, ['--import', register, child], { cwd: repo, encoding: 'utf8',
      env: { ...env, AML_IN_q: JSON.stringify(quorum), AML_IN_p: JSON.stringify(policy),
        AML_IN_b: JSON.stringify(bundle), AML_IN_c: JSON.stringify(challenge) } });
    assert.equal(libs.status, 0, libs.stderr);
    const out = JSON.parse(libs.stdout);
    assert.equal(out.valid, true, `quorum ${name}`);
    assert.equal(out.witness_met, expected, `quorum witness_met ${name}`);
    assert.equal(out.authorized, expected, `quorum authorized ${name}`);
    assert.equal(out.worker_authorized, expected, `worker ${name}`);

    const proc = spawn(process.execPath, ['--import', register, server], { cwd: repo, env, stdio: ['ignore', 'pipe', 'inherit'] });
    try {
      const [chunk] = await once(proc.stdout, 'data');
      const port = Number(String(chunk).trim());
      const response = await fetch(`http://127.0.0.1:${port}/v1/verify-witness-bundle`, { method: 'POST',
        headers: { 'content-type': 'application/json' }, body: JSON.stringify({ bundle, expected_challenge: challenge }) });
      const body = await response.json();
      assert.equal(body.valid, true, `HTTP ${name}: injection engaged`);
      assert.equal(response.status, expected ? 200 : 422, `HTTP ${name}`);
    } finally {
      proc.kill();
      await once(proc, 'exit');
    }
  }
});
