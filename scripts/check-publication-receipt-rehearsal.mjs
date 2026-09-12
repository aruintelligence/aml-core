import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';

function run(args, cwd = process.cwd()) {
  const r = spawnSync(process.execPath, args, { cwd, encoding: 'utf8', shell: false });
  if (r.status !== 0) throw new Error(r.stderr || r.stdout || `${args.join(' ')} failed`);
  return r.stdout;
}
function expectFailure(args, cwd = process.cwd()) {
  const r = spawnSync(process.execPath, args, { cwd, encoding: 'utf8', shell: false });
  if (r.status === 0) throw new Error(`Expected failure: ${args.join(' ')}`);
}

const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'aml-publication-receipt-'));
const transactionPath = path.join(temp, 'transaction.json');
const registryPath = path.join(temp, 'registry.json');
const receiptPath = path.join(temp, 'receipt.json');
run(['scripts/build-publication-transaction.mjs', transactionPath]);
const transaction = JSON.parse(fs.readFileSync(transactionPath, 'utf8'));
const checks = {
  registry_metadata_matches_transaction: true,
  clean_registry_install_passes: true,
  installed_package_version_matches: true,
  installed_api_import_passes: true,
  installed_cli_smoke_test_passes: true
};
const synthetic = {
  synthetic: true,
  package: transaction.package,
  version: transaction.version,
  dist_tag: transaction.dist_tag,
  dist_integrity: transaction.artifact.npm_integrity,
  dist_shasum: transaction.artifact.npm_shasum,
  checks
};
fs.writeFileSync(registryPath, `${JSON.stringify(synthetic, null, 2)}\n`);
run(['scripts/build-publication-receipt.mjs', transactionPath, registryPath, receiptPath]);
run(['scripts/verify-publication-receipt.mjs', receiptPath, transactionPath]);

for (const mutation of [
  r => { r.dist_integrity = 'sha512-tampered'; },
  r => { r.dist_shasum = '0'.repeat(40); },
  r => { r.dist_tag = 'next'; },
  r => { r.version = '9.9.9'; },
  r => { r.checks.clean_registry_install_passes = false; }
]) {
  const copy = structuredClone(synthetic);
  mutation(copy);
  const tampered = path.join(temp, `tampered-${Math.random().toString(16).slice(2)}.json`);
  fs.writeFileSync(tampered, `${JSON.stringify(copy, null, 2)}\n`);
  expectFailure(['scripts/build-publication-receipt.mjs', transactionPath, tampered, path.join(temp, 'should-not-exist.json')]);
}

const receipt = JSON.parse(fs.readFileSync(receiptPath, 'utf8'));
receipt.receipt_root_sha256 = 'f'.repeat(64);
const tamperedReceipt = path.join(temp, 'tampered-receipt.json');
fs.writeFileSync(tamperedReceipt, `${JSON.stringify(receipt, null, 2)}\n`);
expectFailure(['scripts/verify-publication-receipt.mjs', tamperedReceipt, transactionPath]);

console.log(JSON.stringify({
  protocol: 'aml-publication-receipt-rehearsal/1',
  synthetic_registry_observation: true,
  passed: true,
  negative_cases: 6,
  claim_boundary: 'This rehearsal uses synthetic registry observations derived from the local publication transaction. It does not prove npm publication.'
}, null, 2));
