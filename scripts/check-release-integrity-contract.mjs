import fs from 'node:fs';

const contract = JSON.parse(fs.readFileSync('release-integrity-contract.json', 'utf8'));
if (contract.protocol !== 'aml-release-integrity-contract/1') throw new Error('Release integrity protocol mismatch');
if (contract.release_manifest_protocol !== 'aml-immutable-release-manifest/1') throw new Error('Release manifest protocol mismatch');
if (contract.stable_channel !== 'latest') throw new Error('Stable channel must remain latest');
if (contract.monitoring?.scheduled_registry_check_hours !== 6) throw new Error('Scheduled registry interval drift');
for (const key of ['verify_package','verify_version','verify_dist_tag','verify_integrity','verify_shasum','verify_clean_install','verify_api_import','verify_cli_smoke_test','unpublished_state_is_inactive_not_passing']) {
  if (contract.monitoring?.[key] !== true) throw new Error(`Required monitoring control missing: ${key}`);
}
const requiredDrift = ['package_identity_drift','version_drift','dist_tag_drift','integrity_drift','shasum_drift','clean_install_failure','api_import_failure','cli_smoke_failure','source_tag_commit_drift','manifest_root_tamper'];
for (const drift of requiredDrift) if (!contract.drift_classes?.includes(drift)) throw new Error(`Drift class missing: ${drift}`);
console.log(JSON.stringify({ protocol: 'aml-release-integrity-contract-check/1', drift_classes: requiredDrift.length, passed: true }, null, 2));
