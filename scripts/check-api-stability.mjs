import fs from 'node:fs';
import path from 'node:path';

const root = process.cwd();
const contract = JSON.parse(fs.readFileSync(path.join(root, 'api-stability.json'), 'utf8'));
const pkg = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8'));
const declarations = fs.readFileSync(path.join(root, 'index.d.ts'), 'utf8');

function fail(message) {
  console.error(message);
  process.exit(1);
}

if (contract.protocol !== 'aml-api-stability/1') fail('Unsupported API stability protocol');
if (contract.package !== pkg.name) fail('API stability package identity drift');
if (!Array.isArray(contract.protected_exports) || contract.protected_exports.length === 0) fail('Protected export set must not be empty');
if (new Set(contract.protected_exports).size !== contract.protected_exports.length) fail('Protected export set contains duplicates');

const runtime = await import(path.join(root, 'index.js'));
const missingRuntime = contract.protected_exports.filter(name => !(name in runtime));
if (missingRuntime.length) fail(`Protected runtime exports missing: ${missingRuntime.join(', ')}`);

const missingTypes = contract.protected_exports.filter(name => {
  const escaped = name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  return !new RegExp(`\\b(?:function|const|class|interface|type|enum)\\s+${escaped}\\b`).test(declarations);
});
if (missingTypes.length) fail(`Protected TypeScript declarations missing: ${missingTypes.join(', ')}`);

process.stdout.write(`${JSON.stringify({
  protocol: 'aml-api-stability-verification/1',
  valid: true,
  package: pkg.name,
  package_version: pkg.version,
  protected_export_count: contract.protected_exports.length,
  protected_exports: contract.protected_exports,
  runtime_exports_present: true,
  typescript_declarations_present: true,
  claim_boundary: 'Project-controlled API preservation verification; not independent certification or registry publication evidence.'
}, null, 2)}\n`);
