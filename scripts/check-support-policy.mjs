import fs from 'node:fs';

function readJson(path) { return JSON.parse(fs.readFileSync(path, 'utf8')); }
function fail(message) { console.error(message); process.exit(1); }

const support = readJson('support-policy.json');
const project = readJson('project-contract.json');
const upgrade = readJson('upgrade-contract.json');

if (support.protocol !== 'aml-support-policy/1') fail('Unexpected support policy protocol');
if (support.package !== 'aml-core') fail('Support policy package mismatch');
if (support.channels.stable.version !== project.release.stableVersion) fail('Stable support version drifted from project contract');
if (support.channels.stable.tag !== project.release.stableTag) fail('Stable support tag drifted from project contract');
if (support.channels.preview.version !== project.release.previewVersion) fail('Preview support version drifted from project contract');
if (support.channels.preview.tag !== project.release.previewTag) fail('Preview support tag drifted from project contract');
if (support.channels.stable.breaking_changes !== false) fail('Stable channel must not permit breaking changes');
if (support.channels.preview.support_class !== 'preview') fail('Preview support class must remain preview');
if (support.lts.declared !== false) fail('No LTS release has been approved; change requires explicit reviewed policy update');
if (!upgrade.semver_policy.major.includes('breaking')) fail('Upgrade contract no longer states major breaking-change semantics');

const publicFiles = ['README.md', 'ADOPTION.md', 'BREAKTHROUGHS.md', 'COMMERCIAL.md'];
for (const file of publicFiles) {
  if (!fs.existsSync(file)) continue;
  const text = fs.readFileSync(file, 'utf8');
  if (/\b(long[- ]term support|LTS)\b/i.test(text)) fail(`Public LTS claim found in ${file} while support-policy.json declares no LTS release`);
}

console.log(JSON.stringify({
  valid: true,
  protocol: 'aml-support-policy-verification/1',
  stable: support.channels.stable,
  preview: support.channels.preview,
  lts_declared: support.lts.declared,
  claim_boundary: support.claim_boundary
}, null, 2));
