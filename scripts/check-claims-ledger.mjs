import fs from 'node:fs';

const allowedStatuses = new Set(['SHIPPED', 'SPEC', 'DRAFT', 'PITCH']);
const failures = [];

for (const path of ['CLAIMS.md', 'claims.json', 'publications/PROOF_MAP.md', 'publications/EVALUATE_AML_IN_15_MINUTES.md', 'publications/PRESS_FACT_SHEET.md', 'PUBLICATIONS.md']) {
  if (!fs.existsSync(path)) failures.push(`${path}: missing`);
}

if (!fs.existsSync('claims.json')) {
  console.error(JSON.stringify({ verified: false, failures }, null, 2));
  process.exit(1);
}

const ledger = JSON.parse(fs.readFileSync('claims.json', 'utf8'));
if (ledger.type !== 'aml-claims-ledger/1') failures.push('claims.json: wrong type');
if (!Array.isArray(ledger.claims) || ledger.claims.length < 7) failures.push('claims.json: too few claims');

const ids = new Set();
for (const claim of ledger.claims || []) {
  if (!claim.id || ids.has(claim.id)) failures.push(`duplicate or missing claim id: ${claim.id}`);
  ids.add(claim.id);
  if (!allowedStatuses.has(claim.status)) failures.push(`${claim.id}: unsupported status ${claim.status}`);
  if (typeof claim.claim !== 'string' || !claim.claim.trim()) failures.push(`${claim.id}: missing claim text`);
  if (!Array.isArray(claim.evidence)) failures.push(`${claim.id}: evidence must be an array`);
  if (claim.status === 'SHIPPED' && (!claim.evidence || claim.evidence.length === 0)) {
    failures.push(`${claim.id}: SHIPPED claim has no evidence`);
  }
  for (const path of claim.evidence || []) {
    if (!fs.existsSync(path)) failures.push(`${claim.id}: evidence path does not exist: ${path}`);
  }
}

const publications = fs.readFileSync('PUBLICATIONS.md', 'utf8');
for (const needle of ['CLAIMS.md', 'publications/PROOF_MAP.md', 'library/README.md']) {
  if (!publications.includes(needle)) failures.push(`PUBLICATIONS.md: missing ${needle}`);
}

const claimsMd = fs.readFileSync('CLAIMS.md', 'utf8');
for (const needle of ['SHIPPED', 'SPEC', 'DRAFT', 'PITCH', 'does **not** currently claim', 'Office@aruintelligence.com']) {
  if (!claimsMd.includes(needle)) failures.push(`CLAIMS.md: missing ${JSON.stringify(needle)}`);
}

if (!Array.isArray(ledger.non_claims) || ledger.non_claims.length < 4) failures.push('claims.json: non_claims boundary is too small');

if (failures.length) {
  console.error(JSON.stringify({ verified: false, failures }, null, 2));
  process.exit(1);
}

console.log(JSON.stringify({
  verified: true,
  claims: ledger.claims.length,
  shipped_claims: ledger.claims.filter((claim) => claim.status === 'SHIPPED').length,
  pitch_claims: ledger.claims.filter((claim) => claim.status === 'PITCH').length,
  promise: 'Every SHIPPED claim in the machine-readable ledger points to repository evidence.'
}, null, 2));
