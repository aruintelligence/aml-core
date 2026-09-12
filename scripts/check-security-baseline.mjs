import fs from 'node:fs';

function fail(message) {
  console.error(message);
  process.exit(1);
}

const baseline = JSON.parse(fs.readFileSync('security-baseline.json', 'utf8'));
const pkg = JSON.parse(fs.readFileSync('package.json', 'utf8'));
if (baseline.protocol !== 'aml-security-baseline/1') fail('Unsupported AML security baseline protocol');
if (baseline.package !== pkg.name) fail('Security baseline package identity drift');
if (baseline.minimum_node !== pkg.engines?.node) fail('Security baseline Node floor drift');
if (baseline.require_security_policy && !fs.existsSync('SECURITY.md')) fail('SECURITY.md is required');
if (baseline.require_codeql && !fs.existsSync('.github/workflows/codeql.yml')) fail('CodeQL workflow is required');

const runtimeDependencies = Object.keys(pkg.dependencies || {}).sort();
if (baseline.runtime_dependency_policy === 'zero-runtime-dependencies-unless-reviewed' && runtimeDependencies.length !== 0) {
  fail(`Runtime dependencies require explicit security-baseline review: ${runtimeDependencies.join(', ')}`);
}

const securityText = fs.readFileSync('SECURITY.md', 'utf8');
for (const phrase of ['ALLOW/SUPPRESS', 'Ed25519', 'replay', 'revoked', 'Production private key material must never be committed to GitHub']) {
  if (!securityText.includes(phrase)) fail(`SECURITY.md missing required boundary phrase: ${phrase}`);
}

process.stdout.write(`${JSON.stringify({
  protocol: 'aml-security-baseline-verification/1',
  valid: true,
  package: pkg.name,
  runtime_dependency_count: runtimeDependencies.length,
  codeql_required: baseline.require_codeql,
  security_policy_required: baseline.require_security_policy,
  claim_boundary: 'Project-controlled security baseline verification; not an external audit, certification, or vulnerability-free claim.'
}, null, 2)}\n`);
