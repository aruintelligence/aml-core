import fs from 'node:fs';

const required = [
  ['protocol/aml-verifier-cli.md', ['AML Verifier CLI Contract', '--now 2030-01-01T00:05:00Z', 'run-verifier-conformance.mjs']],
  ['protocol/aml-verifier-conformance-result.schema.json', ['"aml-verifier-conformance-result/1"', '"challenge_sha256"', '"witness_vector_sha256"', '"passed"', '"results"']],
  ['protocol/verification-contract-v1.json', ['"aml-verification-contract-snapshot/1"', 'aml-verifier-contract-2026-09-08-01', 'b1ff5a87c7b19ae6338503a58ab6257a5b2add0b']],
  ['protocol/verification-contract-v2.json', ['"aml-verification-contract-snapshot/1"', 'aml-verifier-contract-2026-09-09-01', 'scripts/verify-verifier-conformance-result.mjs']],
  ['protocol/aml-verification-contract-snapshot.schema.json', ['"aml-verification-contract-snapshot/1"', '"locked_paths"', '"source_commit"']],
  ['protocol/aml-verification-contract-migration.schema.json', ['"aml-verification-contract-migration/1"', '"backward-compatible"', '"new_snapshot_may_reinterpret_old_artifacts"']],
  ['protocol/migrations/README.md', ['Every snapshot after the first', 'zero migration edges']],
  ['protocol/aml-verifier-implementation-claim.schema.json', ['"aml-verifier-implementation-claim/1"', '"contract_snapshot_id"', '"external_to_aml_core"']],
  ['protocol/VERIFIER_CONTRACT_VERSIONING.md', ['Published snapshots are immutable', 'Locked path drift requires a new snapshot']],
  ['conformance/verifier/manifest.json', ['"aml-verifier-conformance-manifest/1"', '"golden-valid"', '"tampered-purpose"']],
  ['conformance/verifier/README.md', ['Verifier conformance target', 'Negative results are welcome']],
  ['conformance/verifier-challenge.json', ['"aml-external-verifier-challenge/1"', '"must_bind_exact_challenge_sha256": true', '"must_bind_exact_witness_vector_sha256": true']],
  ['scripts/run-verifier-conformance.mjs', ['challenge_sha256', 'witness_vector_sha256', 'tampered-purpose', 'expired-challenge']],
  ['scripts/verify-verifier-conformance-result.mjs', ['challenge_sha256 does not match exact local challenge bytes', 'witness_vector_sha256 does not match exact local witness-vector bytes']],
  ['scripts/check-verification-contract-snapshot.mjs', ['current verifier snapshot', 'source_commit']],
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
  ['docs/contract-evolution.html', ['AML verifier contract evolution', 'aml-verifier-contract-2026-09-09-01', 'Migration edges:</strong> <span class="good">1']],
  ['docs/llms-verifier.txt', ['AML verifier implementation path', 'aml-verifier-contract-2026-09-09-01', 'Current migration count: 1']],
  ['docs/.well-known/aml.json', ['"go_witness_verifier"', '"verification_contract_migration_count": 1', '"verification_contract_snapshot_id": "aml-verifier-contract-2026-09-09-01"', '"reference_verifier_count": 4']],
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

let catalog = null;
let lineage = null;
try {
  catalog = JSON.parse(fs.readFileSync('protocol/verification-contract-catalog.json', 'utf8'));
  lineage = JSON.parse(fs.readFileSync('protocol/verification-contract-lineage.json', 'utf8'));
} catch (error) {
  failures.push(`unable to parse verifier contract catalog/lineage: ${error.message}`);
}

if (catalog && lineage) {
  if (catalog.schema !== 'aml-verification-contract-catalog/1') failures.push('unexpected verification contract catalog schema');
  if (lineage.schema !== 'aml-verification-contract-lineage/1') failures.push('unexpected verification contract lineage schema');
  if (catalog.current_snapshot !== 'aml-verifier-contract-2026-09-09-01') failures.push('Snapshot 2 must be the current verifier contract');
  if ((catalog.snapshots || []).length !== 2) failures.push('verifier contract catalog must contain exactly two published snapshots');
  if ((catalog.migrations || []).length !== 1) failures.push('verifier contract catalog must contain exactly one published migration');
  if ((lineage.nodes || []).length !== 2) failures.push('verifier contract lineage must contain exactly two nodes');
  if ((lineage.edges || []).length !== 1) failures.push('verifier contract lineage must contain exactly one migration edge');
  const edge = lineage.edges?.[0];
  if (edge?.from_snapshot !== 'aml-verifier-contract-2026-09-08-01' || edge?.to_snapshot !== 'aml-verifier-contract-2026-09-09-01') {
    failures.push('verifier contract lineage edge must run from Snapshot 1 to Snapshot 2');
  }
}

if (failures.length) {
  console.error(JSON.stringify({ verified: false, failures }, null, 2));
  process.exit(1);
}

console.log(JSON.stringify({
  verified: true,
  contract_snapshot_id: catalog.current_snapshot,
  contract_source_commit: catalog.snapshots.find((entry) => entry.snapshot_id === catalog.current_snapshot)?.source_commit || null,
  contract_snapshot_count: catalog.snapshots.length,
  contract_migration_count: catalog.migrations.length,
  reference_languages: ['JavaScript', 'Python', 'Go'],
  reference_claim_count: 4,
  external_witness_count: 0,
  promise: 'The public verifier CLI, immutable historical snapshots, explicit evolution lineage, migration rules, byte-drift guard, implementation claims, conformance harness, challenge-bound evidence, cross-language reference implementations, discovery metadata, and honest external-witness boundary remain present.'
}, null, 2));
