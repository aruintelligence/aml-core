import fs from 'node:fs';
import crypto from 'node:crypto';
import { spawnSync } from 'node:child_process';

const sha256 = b => crypto.createHash('sha256').update(b).digest('hex');
const checkpoint = JSON.parse(fs.readFileSync(process.argv[2] || 'aml-release-transparency-checkpoint.json', 'utf8'));
const contract = JSON.parse(fs.readFileSync('release-transparency-contract.json', 'utf8'));
function git(...args) {
  const r = spawnSync('git', args, { encoding: 'utf8', shell: false });
  if (r.status !== 0) throw new Error(r.stderr || `git ${args.join(' ')} failed`);
  return r.stdout.trim();
}
if (checkpoint.protocol !== contract.checkpoint_protocol) throw new Error('Unexpected checkpoint protocol');
if (!Array.isArray(checkpoint.events) || checkpoint.events.length !== checkpoint.event_count) throw new Error('Event count mismatch');
let previous = null;
for (let i = 0; i < checkpoint.events.length; i++) {
  const event = checkpoint.events[i];
  if (event.sequence !== i + 1) throw new Error('Non-contiguous event sequence');
  if (!contract.allowed_event_types.includes(event.event_type)) throw new Error(`Unsupported event type: ${event.event_type}`);
  if ((event.previous_event_sha256 ?? null) !== previous) throw new Error('Event chain predecessor mismatch');
  const { event_sha256, ...body } = event;
  const computed = sha256(JSON.stringify(body));
  if (computed !== event_sha256) throw new Error('Event hash mismatch');
  previous = computed;
}
if ((checkpoint.events.at(-1)?.event_sha256 || null) !== checkpoint.head_event_sha256) throw new Error('Head event mismatch');
if (git('rev-parse', `${checkpoint.source_tag}^{commit}`) !== checkpoint.source_tag_commit) throw new Error('Source tag commit drift');
for (const [field, file] of [
  ['release_signing_policy_sha256','release-signing-policy.json'],
  ['key_lifecycle_policy_sha256','release-key-lifecycle.json'],
  ['compromise_response_policy_sha256','release-compromise-response.json']
]) {
  if (checkpoint.policies[field] !== sha256(fs.readFileSync(file))) throw new Error(`Policy hash mismatch: ${field}`);
}
const { checkpoint_root_sha256, ...body } = checkpoint;
if (sha256(JSON.stringify(body)) !== checkpoint_root_sha256) throw new Error('Checkpoint root mismatch');
console.log(JSON.stringify({ protocol: 'aml-release-transparency-checkpoint-verification/1', event_count: checkpoint.event_count, checkpoint_root_sha256, passed: true }, null, 2));
