import fs from 'node:fs';

function read(file) { return JSON.parse(fs.readFileSync(file, 'utf8')); }
function fail(message) { console.error(message); process.exit(1); }
function parse(id) {
  const m = /^([a-z0-9-]+)\/([1-9][0-9]*)$/.exec(id);
  if (!m) fail(`Invalid protocol identifier: ${id}`);
  return { id, family: m[1], major: Number(m[2]) };
}

const registry = read('protocol-compatibility.json');
const vectors = read('protocol-negotiation-vectors.json');
if (registry.protocol !== 'aml-protocol-compatibility/1') fail('Unexpected protocol compatibility contract');
if (vectors.protocol !== 'aml-protocol-negotiation-vectors/1') fail('Unexpected negotiation vector contract');
if (registry.policy?.unknown_major !== 'reject' || registry.policy?.major_version_change !== 'breaking') fail('Protocol compatibility policy drift');

const stable = new Set(registry.stable_protocols);
for (const id of stable) parse(id);

function negotiate(offeredId, supportedIds) {
  const offered = parse(offeredId);
  const supported = supportedIds.map(parse);
  if (supported.some(x => x.id === offered.id)) return 'accept_exact';
  const sameFamily = supported.filter(x => x.family === offered.family);
  if (sameFamily.length) {
    const majors = sameFamily.map(x => x.major);
    if (offered.major < Math.min(...majors)) return 'reject_downgrade_major';
    return 'reject_unknown_major';
  }
  return 'reject_unknown_protocol';
}

const results = [];
for (const [index, vector] of vectors.vectors.entries()) {
  const observed = negotiate(vector.offered, vector.supported);
  if (observed !== vector.expected) fail(`Vector ${index} mismatch: expected ${vector.expected}, observed ${observed}`);
  if (vector.expected === 'accept_exact' && stable.has(vector.offered) === false) fail(`Accepted vector ${index} is not in stable protocol registry`);
  results.push({ index, offered: vector.offered, expected: vector.expected, observed });
}

console.log(JSON.stringify({
  valid: true,
  protocol: 'aml-protocol-negotiation-report/1',
  vector_count: results.length,
  results,
  claim_boundary: 'Project-controlled major-version negotiation regression only; not independent interoperability evidence or a standards-body compatibility determination.'
}, null, 2));
