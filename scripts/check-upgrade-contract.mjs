import fs from 'node:fs';

const contract = JSON.parse(fs.readFileSync('upgrade-contract.json','utf8'));
const project = JSON.parse(fs.readFileSync('project-contract.json','utf8'));
const pkg = JSON.parse(fs.readFileSync('package.json','utf8'));

function fail(message){ console.error(message); process.exit(1); }
function semverCore(v){ return v.replace(/^v/,'').split('-')[0].split('.').map(Number); }
function cmp(a,b){ for(let i=0;i<3;i++){ if(a[i]!==b[i]) return a[i]-b[i]; } return 0; }

if(contract.protocol !== 'aml-upgrade-contract/1') fail('Unsupported upgrade contract protocol');
if(contract.package !== pkg.name) fail('Upgrade contract package mismatch');
if(contract.release.stable_version !== project.release.stableVersion) fail('Stable version drift');
if(contract.release.stable_tag !== project.release.stableTag) fail('Stable tag drift');
if(contract.release.preview_version !== project.release.previewVersion) fail('Preview version drift');
if(contract.release.preview_tag !== project.release.previewTag) fail('Preview tag drift');
if(pkg.version !== project.release.stableVersion) fail('package.json no longer matches declared stable control-plane version');
if(cmp(semverCore(contract.release.preview_version), semverCore(contract.release.stable_version)) < 0) fail('Preview version precedes stable version');
if(contract.deprecation_policy.removal_requires_migration_note !== true) fail('Migration note requirement must remain enabled');

console.log(JSON.stringify({protocol:'aml-upgrade-contract-verification/1',valid:true,stable:contract.release.stable_version,preview:contract.release.preview_version,migration_note_required:true,claim_boundary:'Project-controlled release-discipline verification; not a warranty or external certification.'},null,2));
