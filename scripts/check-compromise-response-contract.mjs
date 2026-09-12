import fs from 'node:fs';

const contract = JSON.parse(fs.readFileSync('compromise-response-contract.json', 'utf8'));
if (contract.protocol !== 'aml-release-compromise-response/1') throw new Error('Compromise response protocol mismatch');
if (!Array.isArray(contract.severity_order) || contract.severity_order[0] !== 'observe' || contract.severity_order.at(-1) !== 'recover') throw new Error('Compromise response lifecycle malformed');
for (const [trigger, actions] of Object.entries(contract.triggers || {})) {
  if (!Array.isArray(actions) || !actions.includes('contain') || !actions.includes('verify')) throw new Error(`Trigger ${trigger} must contain and verify`);
}
for (const key of ['do_not_delete_or_rewrite_published_artifact','freeze_automatic_promotion_during_containment','revoked_signers_do_not_count_toward_quorum','replacement_key_requires_explicit_trust_configuration','recovery_requires_fresh_integrity_receipt','recovery_requires_release_sequence_not_older_than_last_accepted','incident_evidence_must_preserve_observed_hashes']) {
  if (contract.controls?.[key] !== true) throw new Error(`Required compromise control missing: ${key}`);
}
console.log(JSON.stringify({ protocol: 'aml-release-compromise-response-check/1', triggers: Object.keys(contract.triggers).length, passed: true }, null, 2));
