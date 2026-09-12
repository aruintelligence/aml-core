import fs from 'node:fs';

const contract = JSON.parse(fs.readFileSync('immutable-release-manifest-contract.json', 'utf8'));
if (contract.protocol !== 'aml-immutable-release-manifest-contract/1') throw new Error('Immutable release manifest contract protocol mismatch');
if (contract.manifest_protocol !== 'aml-immutable-release-manifest/1') throw new Error('Immutable release manifest protocol mismatch');
const required = ['package','version','dist_tag','source_git_tag','source_git_tag_commit','release_sequence','release_signing_threshold','release_readiness_sha256','release_provenance_root_sha256','artifact_sha256','artifact_npm_integrity','artifact_npm_shasum','publication_transaction_root_sha256'];
for (const key of required) if (!contract.required_bindings?.includes(key)) throw new Error(`Manifest binding missing: ${key}`);
for (const key of ['manifest_root_sha256_required','source_tag_must_resolve_to_recorded_commit','published_artifact_identity_must_not_be_rewritten','replacement_release_requires_new_version_or_reviewed_channel_change']) {
  if (contract.immutability?.[key] !== true) throw new Error(`Immutability control missing: ${key}`);
}
console.log(JSON.stringify({ protocol: 'aml-immutable-release-manifest-contract-check/1', required_bindings: required.length, passed: true }, null, 2));
