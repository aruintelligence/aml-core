import fs from 'node:fs';
const status = JSON.parse(fs.readFileSync('release-integrity-status.json', 'utf8'));
const doc = fs.readFileSync('docs/RELEASE_MONITORING_STATE.md', 'utf8');
if (!doc.includes(status.registry_monitoring_state)) throw new Error('Monitoring-state documentation drift');
if (!doc.includes('must never be interpreted as a passing live-registry integrity result')) throw new Error('Monitoring-state claim boundary missing');
console.log(JSON.stringify({ protocol: 'aml-release-integrity-doc-state-check/1', passed: true }, null, 2));
