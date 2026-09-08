#!/usr/bin/env node
import fs from 'node:fs';

const snapshot = JSON.parse(fs.readFileSync('protocol/verification-contract-v1.json', 'utf8'));
const claimPaths = [
  'protocol/verifiers/browser-reference-claim.json',
  'protocol/verifiers/python-reference-claim.json',
  'protocol/verifiers/go-reference-claim.json',
  'protocol/verifiers/http-reference-claim.json'
];

const failures = [];
for (const path of claimPaths) {
  if (!fs.existsSync(path)) {
    failures.push(`${path}: missing`);
    continue;
  }
  const claim = JSON.parse(fs.readFileSync(path, 'utf8'));
  if (claim.schema !== 'aml-verifier-implementation-claim/1') failures.push(`${path}: wrong schema`);
  if (claim.contract_snapshot_id !== snapshot.snapshot_id) failures.push(`${path}: snapshot mismatch`);
  if (claim.contract_source_commit !== snapshot.source_commit) failures.push(`${path}: source commit mismatch`);
  if (claim.external_to_aml_core !== false) failures.push(`${path}: reference claim must not count as external`);
  if (!Array.isArray(claim.artifact_types) || !claim.artifact_types.includes('aml-witness-bundle/1')) failures.push(`${path}: witness artifact missing`);
  if (!claim.claim_boundary?.includes('not')) failures.push(`${path}: claim boundary too weak`);
}

if (failures.length) {
  console.error(JSON.stringify({ verified: false, failures }, null, 2));
  process.exit(1);
}

console.log(JSON.stringify({
  verified: true,
  snapshot_id: snapshot.snapshot_id,
  source_commit: snapshot.source_commit,
  reference_claim_count: claimPaths.length,
  external_claim_count: 0,
  claims: claimPaths
}, null, 2));
