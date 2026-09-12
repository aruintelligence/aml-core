import fs from 'node:fs';
import { spawnSync } from 'node:child_process';

function fail(message) {
  console.error(message);
  process.exit(1);
}

const contract = JSON.parse(fs.readFileSync('cli-contract.json', 'utf8'));
const pkg = JSON.parse(fs.readFileSync('package.json', 'utf8'));
if (contract.protocol !== 'aml-cli-contract/1') fail('Unsupported CLI contract protocol');
if (contract.package !== pkg.name) fail('CLI contract package identity drift');
if (contract.stable_version !== pkg.version) fail('CLI contract stable version drift');
if (!Array.isArray(contract.commands) || new Set(contract.commands).size !== contract.commands.length) fail('CLI contract commands must be unique');

const run = (args) => spawnSync(process.execPath, ['bin/aml.js', ...args], { encoding: 'utf8' });
const help = run(['help']);
if (help.status !== contract.exit_contract.success) fail(`help exited ${help.status}`);
for (const command of contract.commands) {
  if (!help.stdout.includes(`  aml ${command}`)) fail(`Help output does not list command: ${command}`);
}

const version = run(['version']);
if (version.status !== 0) fail(`version exited ${version.status}`);
if (!version.stdout.includes(`v${pkg.version}`)) fail(`version output does not report package version ${pkg.version}`);

const unknown = run(['__aml_unknown_command__']);
if (unknown.status !== contract.exit_contract.usage_or_unknown_command) fail(`Unknown command exit drift: expected ${contract.exit_contract.usage_or_unknown_command}, got ${unknown.status}`);
if (!unknown.stderr.includes('Unknown command')) fail('Unknown command did not emit diagnostic');

const source = fs.readFileSync('bin/aml.js', 'utf8');
const requiredExitLiterals = [
  contract.exit_contract.deploy_evaluation_error,
  contract.exit_contract.deploy_effective_deny_when_required,
  contract.exit_contract.canary_changed_when_fail_on_change
];
for (const code of requiredExitLiterals) {
  if (!source.includes(`process.exit(${code})`)) fail(`Declared nonzero exit code ${code} is not present in AML CLI source`);
}

console.log(JSON.stringify({
  valid: true,
  protocol: contract.protocol,
  package: pkg.name,
  version: pkg.version,
  commands: contract.commands.length,
  checked_exit_codes: Object.values(contract.exit_contract)
}, null, 2));
