import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import { spawnSync } from 'node:child_process';

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'aml-ext-witness-'));
const cli = 'tools/external-witness/aml-external-witness.mjs';
const commit = 'a'.repeat(40);
const evidenceBytes = Buffer.from('synthetic external witness evidence fixture');
const evidenceHash = crypto.createHash('sha256').update(evidenceBytes).digest('hex');
const submission = {
  protocol: 'aml-external-witness-submission/1',
  subject: { repository: 'aruintelligence/aml-core', commit_sha: commit },
  result: 'MIXED',
  reproduction: { command: 'node synthetic-reproduction.mjs', environment: 'CI synthetic fixture' },
  evidence: [{ type: 'synthetic_fixture', sha256: evidenceHash, description: 'CI-only evidence fixture' }],
  claim_boundary: 'Synthetic CI fixture only; not external evidence.'
};
const submissionPath = path.join(tmp, 'submission.json');
fs.writeFileSync(submissionPath, `${JSON.stringify(submission, null, 2)}\n`);

function run(args, expect = 0) {
  const r = spawnSync(process.execPath, [cli, ...args], { encoding: 'utf8' });
  if (r.status !== expect) throw new Error(`Expected exit ${expect}, got ${r.status}: ${r.stderr || r.stdout}`);
  return r;
}

run(['verify', submissionPath]);
const pair = crypto.generateKeyPairSync('ed25519');
const privatePath = path.join(tmp, 'witness-private.pem');
fs.writeFileSync(privatePath, pair.privateKey.export({ type: 'pkcs8', format: 'pem' }), { mode: 0o600 });
const signedPath = path.join(tmp, 'signed.json');
run(['sign', submissionPath, privatePath, signedPath]);
const verified = JSON.parse(run(['verify', signedPath]).stdout);
if (!verified.cryptographic_signature_verified || verified.trust_established || verified.independence_established) throw new Error('Trust separation failed');

const tampered = JSON.parse(fs.readFileSync(signedPath, 'utf8'));
tampered.submission.result = 'PASS';
const tamperedPath = path.join(tmp, 'tampered.json');
fs.writeFileSync(tamperedPath, `${JSON.stringify(tampered, null, 2)}\n`);
run(['verify', tamperedPath], 1);

const outA = path.join(tmp, 'kit-a');
const outB = path.join(tmp, 'kit-b');
for (const out of [outA, outB]) {
  const r = spawnSync(process.execPath, ['scripts/build-external-witness-kit.mjs', out], { encoding: 'utf8' });
  if (r.status !== 0) throw new Error(r.stderr || r.stdout);
}
const manifestA = fs.readFileSync(path.join(outA, 'manifest.json'));
const manifestB = fs.readFileSync(path.join(outB, 'manifest.json'));
if (!manifestA.equals(manifestB)) throw new Error('External witness kit manifest is not deterministic');
const manifest = JSON.parse(manifestA);
if (!/^[0-9a-f]{64}$/.test(manifest.kit_root_sha256)) throw new Error('Invalid kit root');
if (manifest.production_private_key_included !== false || manifest.project_attestation !== false) throw new Error('Invalid claim boundary');

console.log(JSON.stringify({
  protocol: 'aml-external-witness-kit-check/1',
  unsigned_submission_verified: true,
  signed_submission_verified: true,
  tamper_rejected: true,
  signature_trust_separation_verified: true,
  signature_independence_separation_verified: true,
  deterministic_bundle_verified: true,
  synthetic_fixture_only: true,
  external_independent_witness_claimed: false,
  kit_root_sha256: manifest.kit_root_sha256,
  passed: true
}, null, 2));
