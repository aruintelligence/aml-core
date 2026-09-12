import fs from 'node:fs';

const policy = JSON.parse(fs.readFileSync('release-key-lifecycle.json', 'utf8'));
const vectors = JSON.parse(fs.readFileSync('conformance/release-key-lifecycle/v1.json', 'utf8'));
const signing = JSON.parse(fs.readFileSync('release-signing-policy.json', 'utf8'));
if (policy.protocol !== 'aml-release-key-lifecycle/1') throw new Error('Unexpected lifecycle protocol');
if (policy.algorithm !== signing.signature_algorithm) throw new Error('Lifecycle/signing algorithm mismatch');
if (policy.production_private_keys_in_repository !== false || policy.rules.private_key_material_must_not_appear_in_repository !== true) throw new Error('Private-key repository boundary weakened');
for (const v of vectors.vectors) {
  const allowed = (policy.transitions[v.from] || []).includes(v.to);
  if (allowed !== v.allowed) throw new Error(`Lifecycle vector failed: ${v.name}`);
}
for (const v of vectors.quorum_vectors) {
  const revoked = new Set(v.revoked_signers || []);
  const distinct = new Set((v.trusted_signers || []).filter(id => !revoked.has(id)));
  const valid = distinct.size >= v.threshold;
  if (valid !== v.valid) throw new Error(`Quorum vector failed: ${v.name}`);
}
if (signing.authorization.production_threshold < 2) throw new Error('Production threshold unexpectedly below 2');
console.log(JSON.stringify({ protocol: 'aml-release-key-lifecycle-check/1', lifecycle_vectors: vectors.vectors.length, quorum_vectors: vectors.quorum_vectors.length, passed: true }, null, 2));
