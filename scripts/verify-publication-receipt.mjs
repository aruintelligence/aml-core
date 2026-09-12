import fs from 'node:fs';
import crypto from 'node:crypto';

const sha256 = value => crypto.createHash('sha256').update(value).digest('hex');
const readJson = file => JSON.parse(fs.readFileSync(file, 'utf8'));

const receiptPath = process.argv[2];
const transactionPath = process.argv[3];
if (!receiptPath || !transactionPath) {
  throw new Error('Usage: node scripts/verify-publication-receipt.mjs <receipt.json> <transaction.json>');
}

const contract = readJson('publication-receipt-contract.json');
const receipt = readJson(receiptPath);
const transactionBytes = fs.readFileSync(transactionPath);
const transaction = JSON.parse(transactionBytes.toString('utf8'));

if (receipt.protocol !== contract.receipt_protocol) throw new Error('Unexpected receipt protocol');
if (transaction.protocol !== contract.transaction_protocol) throw new Error('Unexpected transaction protocol');
if (receipt.package !== transaction.package || receipt.version !== transaction.version) throw new Error('Receipt package/version mismatch');
if (receipt.dist_tag !== transaction.dist_tag) throw new Error('Receipt dist-tag mismatch');
if (receipt.publication_transaction?.transaction_root_sha256 !== transaction.transaction_root_sha256) throw new Error('Transaction root mismatch');
if (receipt.publication_transaction?.sha256 !== sha256(transactionBytes)) throw new Error('Transaction bytes mismatch');
if (receipt.registry_observation?.dist_integrity !== transaction.artifact?.npm_integrity) throw new Error('Receipt integrity mismatch');
if (receipt.registry_observation?.dist_shasum !== transaction.artifact?.npm_shasum) throw new Error('Receipt shasum mismatch');
for (const key of contract.required_post_publish_checks) {
  if (receipt.checks?.[key] !== true) throw new Error(`Receipt check missing or false: ${key}`);
}
const claimed = receipt.receipt_root_sha256;
const clone = structuredClone(receipt);
delete clone.receipt_root_sha256;
const expected = sha256(JSON.stringify(clone));
if (claimed !== expected) throw new Error('Receipt root mismatch');
console.log(JSON.stringify({ protocol: 'aml-publication-receipt-verification/1', valid: true, package: receipt.package, version: receipt.version, receipt_root_sha256: claimed }, null, 2));
