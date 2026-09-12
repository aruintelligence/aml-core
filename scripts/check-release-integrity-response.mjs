import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';

function run(args) {
  const r = spawnSync(process.execPath, args, { encoding: 'utf8', shell: false });
  if (r.status !== 0) throw new Error(r.stderr || r.stdout || `${args.join(' ')} failed`);
  return r.stdout;
}
function fail(args) {
  const r = spawnSync(process.execPath, args, { encoding: 'utf8', shell: false });
  if (r.status === 0) throw new Error(`Expected failure: ${args.join(' ')}`);
}
const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'aml-integrity-response-'));
const a = path.join(temp, 'manifest-a.json');
const b = path.join(temp, 'manifest-b.json');
run(['scripts/build-immutable-release-manifest.mjs', a]);
run(['scripts/build-immutable-release-manifest.mjs', b]);
if (fs.readFileSync(a, 'utf8') !== fs.readFileSync(b, 'utf8')) throw new Error('Manifest generation is not deterministic');
run(['scripts/verify-release-integrity.mjs', a]);
const tampered = JSON.parse(fs.readFileSync(a, 'utf8'));
tampered.artifact.sha256 = '0'.repeat(64);
const tamperedPath = path.join(temp, 'tampered.json');
fs.writeFileSync(tamperedPath, `${JSON.stringify(tampered, null, 2)}\n`);
fail(['scripts/verify-release-integrity.mjs', tamperedPath]);
const response = JSON.parse(fs.readFileSync('compromise-response-contract.json', 'utf8'));
const requiredTriggers = ['registry_metadata_drift','artifact_integrity_drift','dist_tag_drift','trusted_signing_key_compromise','source_tag_commit_drift','manifest_root_tamper'];
for (const trigger of requiredTriggers) {
  const actions = response.triggers[trigger];
  if (!Array.isArray(actions) || !actions.includes('contain') || !actions.includes('verify')) throw new Error(`Incomplete compromise response for ${trigger}`);
}
if (!response.controls.revoked_signers_do_not_count_toward_quorum) throw new Error('Revoked signer quorum rule missing');
if (!response.controls.recovery_requires_fresh_integrity_receipt) throw new Error('Fresh receipt recovery rule missing');
console.log(JSON.stringify({
  protocol: 'aml-release-integrity-response-rehearsal/1',
  deterministic_manifest: true,
  manifest_tamper_rejected: true,
  compromise_response_triggers_verified: requiredTriggers.length,
  passed: true
}, null, 2));
