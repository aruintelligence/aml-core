import fs from 'node:fs';

const required = [
  ['protocol/aml-verifier-cli.md', ['AML Verifier CLI Contract', '--now 2030-01-01T00:05:00Z', 'run-verifier-conformance.mjs']],
  ['protocol/aml-verifier-conformance-result.schema.json', ['"aml-verifier-conformance-result/1"', '"passed"', '"results"']],
  ['protocol/verification-contract-v1.json', ['"aml-verification-contract-snapshot/1"', 'aml-verifier-contract-2026-09-08-01', 'b1ff5a87c7b19ae6338503a58ab6257a5b2add0b']],
  ['protocol/aml-verification-contract-snapshot.schema.json', ['"aml-verification-contract-snapshot/1"', '"locked_paths"', '"source_commit"']],
  ['protocol/aml-verification-contract-migration.schema.json', ['"aml-verification-contract-migration/1"', '"backward-compatible"', '"new_snapshot_may_reinterpret_old_artifacts"']],
  ['protocol/verification-contract-catalog.json', ['"aml-verification-contract-catalog/1"', '"migration_count"'.replace('migration_count','migrations'), 'aml-verifier-contract-2026-09-08-01']],
  ['protocol/verification-contract-lineage.json', ['"aml-verification-contract-lineage/1"', '"edges": []', 'historical snapshot semantics']],
  ['protocol/migrations/README.md', ['Every snapshot after the first', 'zero migration edges']],
  ['protocol/aml-verifier-implementation-claim.schema.json', ['"aml-verifier-implementation-claim/1"', '"contract_snapshot_id"', '"external_to_aml_core"']],
  ['protocol/VERIFIER_CONTRACT_VERSIONING.md', ['Published snapshots are immutable', 'Locked path drift requires a new snapshot']],
  ['conformance/verifier/manifest.json', ['"aml-verifier-conformance-manifest/1"', '"golden-valid"', '"tampered-purpose"']],
  ['conformance/verifier/README.md', ['Verifier conformance target', 'Negative results are welcome']],
  ['scripts/run-verifier-conformance.mjs', ['aml-verifier-conformance-result/1', 'tampered-purpose', 'expired-challenge']],
  ['scripts/check-verification-contract-snapshot.mjs', ['aml-verification-contract-snapshot/1', 'source_commit']],
  ['scripts/check-verification-contract-drift.mjs', ['byte-identical', 'Publish a new verifier contract snapshot']],
  ['scripts/check-verifier-claims.mjs', ['reference_claim_count', 'external_claim_count']],
  ['scripts/check-contract-lineage.mjs', ['snapshot_count', 'migration_count', 'migration lineage contains cycle']],
  ['scripts/plan-contract-migration.mjs', ['aml-verification-contract-migration-plan/1', 'REQUIRES_HUMAN_CLASSIFICATION']],
  ['scripts/create-verifier-implementation-claim.mjs', ['aml-verifier-implementation-claim/1', 'contract_snapshot_id']],
  ['independent/python/witness-vector.json', ['"aml-witness-bundle/1"', 'ECDSA-P256-SHA256']],
  ['independent/python/verify_witness.py', ['AML_PY_WITNESS_BUNDLE_VALID', 'verify_p256_raw_signature']],
  ['independent/go/go.mod', ['module aml-independent-go-verifier']],
  ['independent/go/main.go', ['AML_GO_WITNESS_BUNDLE_VALID', 'ecdsa.Verify', 'sorted-json-v1']],
  ['independent/go/README.md', ['Go witness verifier', 'does not count as an independent external witness']],
  ['independent/go/verify.sh', ['go run .']],
  ['protocol/verifiers/go-reference.json', ['aru-aml-go-reference', 'Go standard library']],
  ['protocol/verifiers/go-reference-claim.json', ['aml-verifier-implementation-claim/1', 'external_to_aml_core']],
  ['protocol/verifiers/python-reference-claim.json', ['aml-verifier-implementation-claim/1', 'external_to_aml_core']],
  ['protocol/verifiers/browser-reference-claim.json', ['aml-verifier-implementation-claim/1', 'external_to_aml_core']],
  ['protocol/verifiers/http-reference-claim.json', ['aml-verifier-implementation-claim/1', 'external_to_aml_core']],
  ['protocol/verifier-registry.json', ['"reference_verifier_count": 4', '"external_verifier_count": 0', 'aml-verifier-contract-2026-09-08-01']],
  ['docs/EXTERNAL_VERIFIER_10_MINUTES.md', ['Build an external AML verifier in 10 minutes', 'aml-verifier-contract-2026-09-08-01']],
  ['docs/VERIFICATION_CONTRACT_SNAPSHOT.md', ['The immutable Git commit anchors the exact historical contents', 'create-verifier-implementation-claim.mjs']],
  ['docs/CONTRACT_EVOLUTION.md', ['Snapshot N is immutable', 'Current migration count']],
  ['docs/HISTORICAL_VERIFICATION.md', ['Historical invariant', 'may not silently apply newer semantics']],
  ['docs/CONTRACT_MIGRATION_CHECKLIST.md', ['old_snapshot_verification_required', 'new_snapshot_may_reinterpret_old_artifacts']],
  ['docs/IMPLEMENTATION_CLAIMS.md', ['A claim is a declaration', 'A witness record is public reproduction evidence']],
  ['docs/VERIFIER_MATRIX.md', ['Go standard library', 'The next empty row']],
  ['docs/verifier-contract.html', ['ĀML Verifier Contract Snapshot', 'External verifier count:</strong> 0']],
  ['docs/contract-evolution.html', ['AML verifier contract evolution', 'Migration edges:</strong> <span class="good">0']],
  ['docs/llms-verifier.txt', ['AML verifier implementation path', 'aml-verifier-contract-2026-09-08-01', 'Current migration count: 0']],
  ['docs/.well-known/aml.json', ['"go_witness_verifier"', '"verification_contract_migration_count": 0', '"reference_verifier_count": 4']],
  ['VERIFY.md', ['Verify AML without trusting AML', 'Contract evolution without rewriting history', 'aml-verifier-contract-2026-09-08-01']],
  ['WITNESSES.json', ['"external_witness_count": 0', '"negative_results_allowed": true']]
];

const failures = [];
for (const [path, needles] of required) {
  if (!fs.existsSync(path)) {
    failures.push(`${path}: missing`);
    continue;
  }
  const text = fs.readFileSync(path, 'utf8');
  for (const needle of needles) {
    if (!text.includes(needle)) failures.push(`${path}: missing ${JSON.stringify(needle)}`);
  }
}

if (failures.length) {
  console.error(JSON.stringify({ verified: false, failures }, null, 2));
  process.exit(1);
}

console.log(JSON.stringify({
  verified: true,
  contract_snapshot_id: 'aml-verifier-contract-2026-09-08-01',
  contract_source_commit: 'b1ff5a87c7b19ae6338503a58ab6257a5b2add0b',
  contract_snapshot_count: 1,
  contract_migration_count: 0,
  reference_languages: ['JavaScript', 'Python', 'Go'],
  reference_claim_count: 4,
  external_witness_count: 0,
  promise: 'The public verifier CLI, immutable snapshot, explicit evolution lineage, migration rules, byte-drift guard, implementation claims, conformance harness, cross-language reference implementations, discovery metadata, and honest external-witness boundary remain present.'
}, null, 2));
