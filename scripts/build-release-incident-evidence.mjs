import fs from 'node:fs';
import crypto from 'node:crypto';

const sha256 = value => crypto.createHash('sha256').update(value).digest('hex');
const readJson = file => JSON.parse(fs.readFileSync(file, 'utf8'));
const trigger = process.argv[2] || 'registry_metadata_drift';
const observedPath = process.argv[3];
if (!observedPath) throw new Error('Usage: node scripts/build-release-incident-evidence.mjs <trigger> <observed-json> [out]');
const response = readJson('compromise-response-contract.json');
const observedBytes = fs.readFileSync(observedPath);
const actions = response.triggers?.[trigger];
if (!actions) throw new Error(`Unknown compromise trigger: ${trigger}`);
const evidence = {
  protocol: 'aml-release-incident-evidence/1',
  trigger,
  prescribed_actions: actions,
  observed_sha256: sha256(observedBytes),
  observed: JSON.parse(observedBytes.toString('utf8')),
  controls: {
    preserve_observed_hashes: response.controls.incident_evidence_must_preserve_observed_hashes,
    automatic_promotion_frozen: response.controls.freeze_automatic_promotion_during_containment,
    published_artifact_rewrite_forbidden: response.controls.do_not_delete_or_rewrite_published_artifact
  },
  claim_boundary: response.claim_boundary
};
evidence.incident_root_sha256 = sha256(JSON.stringify(evidence));
const out = `${JSON.stringify(evidence, null, 2)}\n`;
fs.writeFileSync(process.argv[4] || 'aml-release-incident-evidence.json', out);
process.stdout.write(out);
