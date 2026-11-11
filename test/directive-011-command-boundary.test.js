import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { executeAccountableIntent, signExecutionReceipt, createMeaningManifest,
  signMeaningManifest, createMeaningLineage, appendMeaningLineage, createSemanticReleaseProof,
  createInTotoSemanticReleaseStatement } from '../index.js';
import { commandOutcome, commandAuthorizationDecision, withCommandAuthorization }
  from '../runtime/commandAuthorization.js';

test('contradictory, inherited, incomplete and accessor authorization objects cannot exit successfully', () => {
  const valid = withCommandAuthorization({ valid: true }, commandAuthorizationDecision(
    { pinned: true }, ['pinned'], { pinned: 'AML_AUTHZ_PIN_REQUIRED' }));
  assert.equal(commandOutcome(valid).exitCode, 0, 'positive control');
  for (const change of [
    { decision: 'deny' }, { decision: undefined }, { schema: 'unknown/1' },
    { reasons: ['AML_AUTHZ_DENY'] }, { required: [] }, { required: ['a', 'a'] }
  ]) {
    const outcome = commandOutcome({ ...valid, authorization: { ...valid.authorization, ...change } });
    assert.equal(outcome.exitCode, 3);
    assert.equal(outcome.output.authorized, false);
    assert.equal(outcome.output.authorization.authorized, false);
  }
  const inherited = Object.assign(Object.create({ authorized: true }), valid.authorization);
  delete inherited.authorized;
  assert.equal(commandOutcome({ ...valid, authorization: inherited }).exitCode, 3);
  const accessor = { ...valid.authorization };
  Object.defineProperty(accessor, 'authorized', { get() { throw new Error('must not invoke'); } });
  assert.equal(commandOutcome({ ...valid, authorization: accessor }).exitCode, 3);
});

test('real verification CLIs deny execution while explicit diagnostics preserve artifact checks', t => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'aml-011-cli-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const save = (name, data) => {
    const file = path.join(dir, name);
    fs.writeFileSync(file, JSON.stringify(data));
    return file;
  };
  const run = (script, args, diagnostic = false) => spawnSync(process.execPath,
    [script, ...args, ...(diagnostic ? ['--diagnostic-only'] : [])], { encoding: 'utf8' });
  const key = crypto.generateKeyPairSync('ed25519').privateKey.export({ type: 'pkcs8', format: 'pem' });
  const receipt = executeAccountableIntent({ transmission: 'test', nodes: [
    { type: 'engram', identifier: 'card', properties: { purpose: 'Explain', attention_cost: 1, restoration_value: 5 } }
  ] });
  const sources = { 'examples/simple.aml': fs.readFileSync('examples/simple.aml', 'utf8') };
  const before = createMeaningManifest(sources);
  const afterSources = { 'examples/simple.aml': sources['examples/simple.aml'] + '\n// same meaning\n' };
  const after = createMeaningManifest(afterSources);
  const a = signMeaningManifest(before, key);
  const b = signMeaningManifest(after, key);
  let lineage = appendMeaningLineage(createMeaningLineage(), before, a);
  lineage = appendMeaningLineage(lineage, after, b);
  const proof = createSemanticReleaseProof({ before_manifest: before, before_attestation: a,
    after_manifest: after, after_attestation: b, lineage, before_sources: sources,
    after_sources: afterSources, private_key_pem: key, release_id: 'synthetic' });
  const receiptFile = save('receipt.json', receipt);
  const proofFile = save('proof.json', proof);
  const cases = [
    ['bin/aml.js', ['verify-receipt', receiptFile]],
    ['bin/aml.js', ['replay-receipt', receiptFile]],
    ['bin/aml.js', ['verify-signed-receipt', save('signed.json', signExecutionReceipt(receipt, key))]],
    ['bin/aml.js', ['verify-audit', save('audit.json', receipt.runtime_audit_stream)]],
    ['bin/aml-meaning.js', ['verify-manifest', save('manifest.json', before)]],
    ['bin/aml-meaning.js', ['verify-attestation', save('attestation.json', a), save('meaning.json', before)]],
    ['bin/aml-meaning.js', ['examples/simple.aml', 'examples/simple.aml']],
    ['bin/aml-release-proof.js', [proofFile]],
    ['bin/aml-release-proof.js', ['verify-in-toto', save('intoto.json', createInTotoSemanticReleaseStatement(proof))]],
    ['scripts/semantic-release-gate.js', [proofFile]]
  ];
  for (const [script, args] of cases) {
    const label = `${script} ${args[0]}`;
    const plain = run(script, args);
    assert.equal(plain.status, 3, `${label}: ${plain.stderr} ${plain.stdout}`);
    const report = JSON.parse(plain.stdout);
    assert.equal(report.valid, true, label);
    assert.equal(report.authorized, false, label);
    assert.equal(report.authorization.decision, 'deny', label);
    const diagnostic = run(script, args, true);
    assert.equal(diagnostic.status, 0, `${label}: ${diagnostic.stderr}`);
    const output = JSON.parse(diagnostic.stdout);
    assert.equal(output.authorized, false, label);
    assert.equal(output.authorization.authorized, false, label);
    assert.equal(output.diagnostic_only, true, label);
    assert.equal(output.decision_use, 'NOT AN AUTHORIZATION DECISION', label);
  }
  const corrupt = save('corrupt.json', { ...proof, proof_sha256: '0'.repeat(64) });
  assert.equal(run('bin/aml-release-proof.js', [corrupt], true).status, 1, 'diagnostic cannot hide invalid proof');
});

test('Python negotiation compatibility is never permission to execute', t => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'aml-011-negotiate-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const file = path.join(dir, 'capabilities.json');
  fs.writeFileSync(file, JSON.stringify({ wire_versions: ['1.0'], capabilities: ['verify'] }));
  for (const diagnostic of [false, true]) {
    const result = spawnSync('python3', ['independent/python/wire_runtime.py', 'negotiate', file, file,
      ...(diagnostic ? ['--diagnostic-only'] : [])], { encoding: 'utf8' });
    assert.equal(result.status, diagnostic ? 0 : 3, result.stderr + result.stdout);
    const output = JSON.parse(result.stdout);
    assert.equal(output.accepted, true);
    assert.equal(output.authorized, false);
    assert.equal(output.authorization.decision, 'deny');
  }
});
