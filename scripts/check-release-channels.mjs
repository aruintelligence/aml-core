import fs from 'node:fs';

function read(file) { return JSON.parse(fs.readFileSync(file, 'utf8')); }
function fail(message) { console.error(message); process.exit(1); }

const project = read('project-contract.json');
const channels = read('release-channels.json');
const rollback = read('rollback-contract.json');
const pkg = read('package.json');

if (channels.protocol !== 'aml-release-channels/1') fail('Unexpected release-channel protocol');
if (rollback.protocol !== 'aml-rollback-contract/1') fail('Unexpected rollback protocol');
if (channels.package !== pkg.name || rollback.package !== pkg.name) fail('Package identity mismatch');

const stable = channels.channels?.stable;
const preview = channels.channels?.preview;
if (!stable || !preview) fail('Stable and preview channels are required');
if (stable.version !== project.release.stableVersion || stable.git_tag !== project.release.stableTag) fail('Stable channel drifted from project contract');
if (preview.version !== project.release.previewVersion || preview.git_tag !== project.release.previewTag) fail('Preview channel drifted from project contract');
if (stable.npm_dist_tag !== 'latest') fail('Stable npm dist-tag must be latest');
if (preview.npm_dist_tag !== 'next') fail('Preview npm dist-tag must be next');
if (stable.version.includes('-')) fail('Stable channel cannot resolve to prerelease');
if (!preview.version.includes('-')) fail('Preview channel must resolve to prerelease');
if (stable.version === preview.version || stable.git_tag === preview.git_tag) fail('Stable and preview channels must remain isolated');
if (rollback.rollback_target.version !== stable.version || rollback.rollback_target.git_tag !== stable.git_tag) fail('Rollback target must be the canonical stable release');
if (pkg.version !== stable.version) fail('Control-plane package version must equal stable version');

console.log(JSON.stringify({
  valid: true,
  protocol: 'aml-release-channel-verification/1',
  package: pkg.name,
  stable,
  preview,
  rollback_target: rollback.rollback_target,
  claim_boundary: 'Project-controlled release-channel and rollback contract verification only; not proof of registry publication.'
}, null, 2));
