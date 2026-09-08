import fs from 'node:fs';

const required = [
  ['protocol/aml-verifier-cli.md', ['AML Verifier CLI Contract', '--now 2030-01-01T00:05:00Z', 'run-verifier-conformance.mjs']],
  ['protocol/aml-verifier-conformance-result.schema.json', ['"aml-verifier-conformance-result/1"', '"passed"', '"results"']],
  ['conformance/verifier/manifest.json', ['"aml-verifier-conformance-manifest/1"', '"golden-valid"', '"tampered-purpose"']],
  ['conformance/verifier/README.md', ['Verifier conformance target', 'Negative results are welcome']],
  ['scripts/run-verifier-conformance.mjs', ['aml-verifier-conformance-result/1', 'tampered-purpose', 'expired-challenge']],
  ['independent/python/witness-vector.json', ['"aml-witness-bundle/1"', 'ECDSA-P256-SHA256']],
  ['independent/python/verify_witness.py', ['AML_PY_WITNESS_BUNDLE_VALID', 'verify_p256_raw_signature']],
  ['independent/go/go.mod', ['module aml-independent-go-verifier']],
  ['independent/go/main.go', ['AML_GO_WITNESS_BUNDLE_VALID', 'ecdsa.Verify', 'sorted-json-v1']],
  ['independent/go/README.md', ['Go witness verifier', 'does not count as an independent external witness']],
  ['independent/go/verify.sh', ['go run .']],
  ['protocol/verifiers/go-reference.json', ['aru-aml-go-reference', 'Go standard library']],
  ['protocol/verifier-registry.json', ['"reference_verifier_count": 4', '"external_verifier_count": 0', 'aml-verifier-conformance-result/1']],
  ['docs/EXTERNAL_VERIFIER_10_MINUTES.md', ['Build an external AML verifier in 10 minutes', 'run-verifier-conformance.mjs']],
  ['docs/VERIFIER_MATRIX.md', ['Go standard library', 'The next empty row']],
  ['docs/llms-verifier.txt', ['AML verifier implementation path', 'Go standard library', 'Disagreement is acceptable']],
  ['docs/.well-known/aml.json', ['"go_witness_verifier"', '"verifier_conformance_harness"', '"reference_verifier_count": 4']],
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
  reference_languages: ['JavaScript', 'Python', 'Go'],
  external_witness_count: 0,
  promise: 'The public verifier CLI, conformance harness, cross-language reference implementations, discovery metadata, and honest external-witness boundary remain present.'
}, null, 2));
