import fs from 'node:fs';
import crypto from 'node:crypto';

const sha256 = value => crypto.createHash('sha256').update(value).digest('hex');
const readJson = file => JSON.parse(fs.readFileSync(file, 'utf8'));

const transactionPath = process.argv[2];
const registryPath = process.argv[3];
const outputPath = process.argv[4] || 'aml-publication-receipt.json';
if (!transactionPath || !registryPath) {
  throw new Error('Usage: node scripts/build-publication-receipt.mjs <transaction.json> <registry-observation.json> [output.json]');
}

const contract = readJson('publication-receipt-contract.json');
const transactionBytes = fs.readFileSync(transactionPath);
const transaction = JSON.parse(transactionBytes.toString('utf8'));
const registry = readJson(registryPath);

if (transaction.protocol !== contract.transaction_protocol) throw new Error('Unexpected publication transaction protocol');
if (registry.package !== transaction.package) throw new Error('Registry package mismatch');
if (registry.version !== transaction.version) throw new Error('Registry version mismatch');
if (registry.dist_tag !== transaction.dist_tag) throw new Error('Registry dist-tag mismatch');
if (registry.dist_integrity !== transaction.artifact?.npm_integrity) throw new Error('Registry integrity mismatch');
if (registry.dist_shasum !== transaction.artifact?.npm_shasum) throw new Error('Registry shasum mismatch');

const checks = registry.checks || {};
for (const key of contract.required_post_publish_checks) {
  if (checks[key] !== true) throw new Error(`Required post-publication check failed or missing: ${key}`);
}

const receipt = {
  protocol: contract.receipt_protocol,
  package: transaction.package,
  version: transaction.version,
  registry: contract.registry,
  dist_tag: transaction.dist_tag,
  publication_transaction: {
    transaction_root_sha256: transaction.transaction_root_sha256,
    sha256: sha256(transactionBytes)
  },
  registry_observation: {
    package: registry.package,
    version: registry.version,
    dist_tag: registry.dist_tag,
    dist_integrity: registry.dist_integrity,
    dist_shasum: registry.dist_shasum
  },
  checks: Object.fromEntries(contract.required_post_publish_checks.map(key => [key, true])),
  claim_boundary: contract.claim_boundary
};
receipt.receipt_root_sha256 = sha256(JSON.stringify(receipt));
fs.writeFileSync(outputPath, `${JSON.stringify(receipt, null, 2)}\n`);
process.stdout.write(`${JSON.stringify(receipt, null, 2)}\n`);
