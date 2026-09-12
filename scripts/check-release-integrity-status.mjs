import fs from 'node:fs';

const status = JSON.parse(fs.readFileSync('release-integrity-status.json', 'utf8'));
const publication = JSON.parse(fs.readFileSync('publication-contract.json', 'utf8'));
if (status.protocol !== 'aml-release-integrity-status/1') throw new Error('Release integrity status protocol mismatch');
if (status.stable_target.package !== publication.package) throw new Error('Status package drift');
if (status.stable_target.version !== publication.stable.version) throw new Error('Status version drift');
if (status.stable_target.dist_tag !== publication.stable.dist_tag) throw new Error('Status dist-tag drift');
if (status.stable_target.source_tag !== publication.stable.git_tag) throw new Error('Status source-tag drift');
if (status.registry_monitoring_state !== 'inactive_until_publication') throw new Error('Unexpected monitoring state before confirmed publication');
if (!status.interpretation.inactive_until_publication_is_not_pass || !status.interpretation.synthetic_rehearsal_is_not_live_registry_evidence || !status.interpretation.live_registry_verification_required_after_publication) throw new Error('Monitoring claim boundary weakened');
console.log(JSON.stringify({ protocol: 'aml-release-integrity-status-check/1', passed: true }, null, 2));
