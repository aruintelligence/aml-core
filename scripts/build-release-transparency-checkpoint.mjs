import fs from 'node:fs';
import crypto from 'node:crypto';
import { spawnSync } from 'node:child_process';

const sha256 = b => crypto.createHash('sha256').update(b).digest('hex');
const read = f => fs.readFileSync(f);
const readJson = f => JSON.parse(read(f).toString('utf8'));
function git(...args) {
  const r = spawnSync('git', args, { encoding: 'utf8', shell: false });
  if (r.status !== 0) throw new Error(r.stderr || `git ${args.join(' ')} failed`);
  return r.stdout.trim();
}
const contract = readJson('release-transparency-contract.json');
const publication = readJson('publication-contract.json');
const eventSubjects = [
  ['release_manifest','release-integrity-contract.json'],
  ['key_trust','release-signing-policy.json'],
  ['key_overlap','release-key-lifecycle.json'],
  ['incident_evidence','release-compromise-response.json']
];
let previous = null;
const events = eventSubjects.map(([event_type, subject], i) => {
  const event = {
    protocol: contract.event_protocol,
    sequence: i + 1,
    event_type,
    subject,
    subject_sha256: sha256(read(subject)),
    previous_event_sha256: previous
  };
  const eventHash = sha256(JSON.stringify(event));
  previous = eventHash;
  return { ...event, event_sha256: eventHash };
});
const checkpoint = {
  protocol: contract.checkpoint_protocol,
  repository_commit: git('rev-parse','HEAD'),
  source_tag: publication.stable.git_tag,
  source_tag_commit: git('rev-parse', `${publication.stable.git_tag}^{commit}`),
  policies: {
    release_signing_policy_sha256: sha256(read('release-signing-policy.json')),
    key_lifecycle_policy_sha256: sha256(read('release-key-lifecycle.json')),
    compromise_response_policy_sha256: sha256(read('release-compromise-response.json'))
  },
  event_count: events.length,
  head_event_sha256: events.at(-1)?.event_sha256 || null,
  events,
  claim_boundary: contract.claim_boundary
};
checkpoint.checkpoint_root_sha256 = sha256(JSON.stringify(checkpoint));
const out = `${JSON.stringify(checkpoint, null, 2)}\n`;
fs.writeFileSync(process.argv[2] || 'aml-release-transparency-checkpoint.json', out);
process.stdout.write(out);
