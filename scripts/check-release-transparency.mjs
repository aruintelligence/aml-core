import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';

function run(args) {
  const r = spawnSync(process.execPath, args, { encoding: 'utf8', shell: false });
  if (r.status !== 0) throw new Error(r.stderr || r.stdout || `${args.join(' ')} failed`);
  return r.stdout;
}
function expectFailure(args) {
  const r = spawnSync(process.execPath, args, { encoding: 'utf8', shell: false });
  if (r.status === 0) throw new Error(`Expected failure: ${args.join(' ')}`);
}
run(['scripts/check-release-key-lifecycle.mjs']);
const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'aml-release-transparency-'));
const checkpointPath = path.join(temp, 'checkpoint.json');
run(['scripts/build-release-transparency-checkpoint.mjs', checkpointPath]);
run(['scripts/verify-release-transparency-checkpoint.mjs', checkpointPath]);
const original = JSON.parse(fs.readFileSync(checkpointPath, 'utf8'));
for (const mutate of [
  c => { c.events[1].subject_sha256 = '0'.repeat(64); },
  c => { c.events[2].previous_event_sha256 = 'f'.repeat(64); },
  c => { c.events[0].sequence = 9; },
  c => { c.checkpoint_root_sha256 = 'a'.repeat(64); }
]) {
  const c = structuredClone(original);
  mutate(c);
  const p = path.join(temp, `tampered-${Math.random().toString(16).slice(2)}.json`);
  fs.writeFileSync(p, `${JSON.stringify(c, null, 2)}\n`);
  expectFailure(['scripts/verify-release-transparency-checkpoint.mjs', p]);
}
console.log(JSON.stringify({ protocol: 'aml-release-transparency-rehearsal/1', negative_cases: 4, synthetic_key_ids_only: true, passed: true, claim_boundary: 'Project-controlled rehearsal; not an external witness or production credential rotation.' }, null, 2));
