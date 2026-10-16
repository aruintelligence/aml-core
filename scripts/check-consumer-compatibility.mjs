import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFileSync, spawnSync } from 'node:child_process';
import { webcrypto } from 'node:crypto';
import { sealBrowserReceipt } from '../docs/aml-browser-integrity.js';
import { createBrowserEvidence } from '../docs/aml-browser-evidence.js';
import { createVerificationChallenge } from '../docs/aml-verification-challenge.js';
import { createSessionAttestation } from '../docs/aml-session-attestation.js';
import { createWitnessBundle, verifyWitnessBundle } from '../docs/aml-witness-bundle.js';
import { witnessVerificationReport } from '../docs/aml-verification-report.js';
import { createVerifierKeyPair, signVerificationReport } from '../docs/aml-signed-verification-report.js';
import { createSignedVerificationQuorum } from '../docs/aml-signed-verification-quorum.js';

const root = process.cwd();
const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'aml-consumer-compat-'));
let tarballPath = null;

function run(command, args, cwd) {
  return execFileSync(command, args, {
    cwd,
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'pipe']
  }).trim();
}

function resolveNpmCli() {
  const nodeDir = path.dirname(process.execPath);
  const candidates = process.platform === 'win32'
    ? [path.join(nodeDir, 'node_modules', 'npm', 'bin', 'npm-cli.js')]
    : [
        path.join(nodeDir, '..', 'lib', 'node_modules', 'npm', 'bin', 'npm-cli.js'),
        path.join(nodeDir, 'node_modules', 'npm', 'bin', 'npm-cli.js')
      ];
  const found = candidates.find(candidate => fs.existsSync(candidate));
  if (!found) throw new Error(`Unable to locate npm-cli.js next to Node runtime ${process.execPath}`);
  return path.resolve(found);
}

function runNpm(args, cwd) {
  return run(process.execPath, [resolveNpmCli(), ...args], cwd);
}

try {
  const matrix = JSON.parse(fs.readFileSync(path.join(root, 'compatibility-matrix.json'), 'utf8'));
  const pkg = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8'));
  if (matrix.package !== pkg.name) throw new Error('Compatibility matrix package name does not match package.json');
  if (matrix.runtime?.node_engine !== pkg.engines?.node) throw new Error('Compatibility matrix Node engine does not match package.json');

  const packResult = JSON.parse(runNpm(['pack', '--json', '--pack-destination', tempRoot], root))[0];
  tarballPath = path.join(tempRoot, packResult.filename);
  if (!fs.existsSync(tarballPath)) throw new Error(`npm pack did not create ${tarballPath}`);

  fs.writeFileSync(path.join(tempRoot, 'package.json'), '{"private":true,"type":"module"}\n');
  fs.writeFileSync(path.join(tempRoot, 'sample.aml'), `transmission "consumer-compat" {\n  title: "Consumer compatibility"\n  engram proof {\n    value: "Cross-platform package smoke test"\n    purpose: "verify installed AML consumer path"\n    memory_role: "compatibility_fixture"\n    user_effect: "clarity"\n    attention_cost: 1\n    restoration_value: 3\n  }\n}\n`);

  runNpm(['install', '--ignore-scripts', '--save-exact', tarballPath], tempRoot);
  const apiOutput = run(process.execPath, ['-e', "import('aml-core').then(m=>{if(!m||Object.keys(m).length===0||typeof m.applyLockedHttpDecision!=='function'||typeof m.evaluateLockedHttpAndRender!=='function')process.exit(2);console.log(Object.keys(m).length)}).catch(e=>{console.error(e);process.exit(1)})"], tempRoot);

  const installedRoot = path.join(tempRoot, 'node_modules', pkg.name);
  const doctorOutput = run(process.execPath, [path.join(installedRoot, 'bin', 'aml-doctor.js')], tempRoot);
  const validateOutput = run(process.execPath, [path.join(installedRoot, 'bin', 'aml.js'), 'validate', 'sample.aml'], tempRoot);
  fs.copyFileSync(path.join(root, 'examples', 'consumer', 'quickstart.mjs'), path.join(tempRoot, 'quickstart.mjs'));
  const quickstart = JSON.parse(run(process.execPath, ['quickstart.mjs'], tempRoot));
  if (quickstart.allowed !== 1 || quickstart.suppressed !== 1 || quickstart.verified !== true) {
    throw new Error('Installed-package API quickstart did not reproduce ALLOW/SUPPRESS with a verified receipt');
  }
  runNpm(['exec', '--', 'aml', 'execute', 'intent.json', 'calm_default', 'context.json', 'cli-receipt.json'], tempRoot);
  const cliReceipt = JSON.parse(fs.readFileSync(path.join(tempRoot, 'cli-receipt.json'), 'utf8'));
  const cliVerification = JSON.parse(runNpm(['exec', '--', 'aml', 'verify-receipt', 'cli-receipt.json'], tempRoot));
  if (cliReceipt.selected_render?.allowed !== 1 || cliReceipt.selected_render?.suppressed !== 1 || !cliVerification.verified) {
    throw new Error('Installed-package CLI execution or receipt verification failed');
  }

  if (!globalThis.crypto?.subtle) globalThis.crypto = webcrypto;
  const browserReceipt = await sealBrowserReceipt({ schema: 'aml-dom-receipt/1', decisions: [] });
  const browserEvidence = await createBrowserEvidence(browserReceipt, { url: 'https://example.test/' });
  const challenge = createVerificationChallenge({ ttl_ms: 120000 });
  const attestation = await createSessionAttestation({ evidence: browserEvidence, challenge });
  const bundle = await createWitnessBundle({ evidence: browserEvidence, challenge, attestation });
  fs.writeFileSync(path.join(tempRoot, 'witness.json'), `${JSON.stringify(bundle)}\n`);
  fs.writeFileSync(path.join(tempRoot, 'held-challenge.json'), `${JSON.stringify(challenge)}\n`);
  const witnessValid = JSON.parse(runNpm(['exec', '--', 'aml', 'verify-witness', 'witness.json', 'held-challenge.json'], tempRoot));
  if (!witnessValid.valid || witnessValid.reason !== 'AML_WITNESS_BUNDLE_VALID') {
    throw new Error('Installed-package witness CLI did not verify the retained challenge');
  }
  const differentChallenge = { ...challenge, issued_at: new Date(Date.parse(challenge.issued_at) - 1000).toISOString() };
  fs.writeFileSync(path.join(tempRoot, 'other-challenge.json'), `${JSON.stringify(differentChallenge)}\n`);
  const rejectedWitness = spawnSync(process.execPath, [path.join(installedRoot, 'bin', 'aml.js'),
    'verify-witness', 'witness.json', 'other-challenge.json'], { cwd: tempRoot, encoding: 'utf8' });
  if (rejectedWitness.status !== 2 ||
      JSON.parse(rejectedWitness.stdout).reason !== 'AML_WITNESS_BUNDLE_CHALLENGE_MISMATCH') {
    throw new Error('Installed-package witness CLI accepted a different retained challenge');
  }

  const witnessCheck = await verifyWitnessBundle(bundle, { expectedChallenge: challenge });
  const reportA = witnessVerificationReport(bundle, witnessCheck, { verifier: 'compat-a' });
  const reportB = witnessVerificationReport(bundle, witnessCheck, { verifier: 'compat-b' });
  const signedA = await signVerificationReport(reportA, await createVerifierKeyPair());
  const signedB = await signVerificationReport(reportB, await createVerifierKeyPair());
  const signedQuorum = await createSignedVerificationQuorum([signedA, signedB], { threshold: 2 });
  fs.writeFileSync(path.join(tempRoot, 'signed-quorum.json'), `${JSON.stringify(signedQuorum)}\n`);
  const quorumValid = JSON.parse(runNpm(['exec', '--', 'aml', 'verify-signed-quorum', 'signed-quorum.json'], tempRoot));
  if (!quorumValid.valid || !quorumValid.threshold_met) {
    throw new Error('Installed-package signed quorum CLI did not verify the saved threshold');
  }
  const heldPolicy = {
    schema: 'aml-signed-quorum-held-policy/1', prototype: true,
    artifact_type: signedQuorum.artifact_type, artifact_hash: signedQuorum.artifact_hash,
    trusted_key_fingerprints: [signedA.verifier_key_fingerprint, signedB.verifier_key_fingerprint],
    threshold: 2
  };
  fs.writeFileSync(path.join(tempRoot, 'held-policy.json'), `${JSON.stringify(heldPolicy)}\n`);
  const policyValid = JSON.parse(runNpm(['exec', '--', 'aml', 'verify-signed-quorum',
    'signed-quorum.json', '--policy', 'held-policy.json'], tempRoot));
  if (!policyValid.valid || !policyValid.threshold_met || !policyValid.policy_met) {
    throw new Error('Installed-package signed quorum CLI did not enforce verifier-held policy');
  }
  const otherPolicy = { ...heldPolicy, trusted_key_fingerprints: [
    signedA.verifier_key_fingerprint, '0'.repeat(64)
  ] };
  fs.writeFileSync(path.join(tempRoot, 'other-policy.json'), `${JSON.stringify(otherPolicy)}\n`);
  const policyRejected = spawnSync(process.execPath, [path.join(installedRoot, 'bin', 'aml.js'),
    'verify-signed-quorum', 'signed-quorum.json', '--policy', 'other-policy.json'],
  { cwd: tempRoot, encoding: 'utf8' });
  const rejectedPolicyResult = JSON.parse(policyRejected.stdout);
  if (policyRejected.status !== 2 || !rejectedPolicyResult.valid ||
      !rejectedPolicyResult.threshold_met || rejectedPolicyResult.policy_met !== false) {
    throw new Error('Installed-package signed quorum CLI accepted an untrusted verifier key');
  }
  const inflatedQuorum = structuredClone(signedQuorum);
  inflatedQuorum.summary.distinct_keys += 1;
  fs.writeFileSync(path.join(tempRoot, 'inflated-quorum.json'), `${JSON.stringify(inflatedQuorum)}\n`);
  const rejectedQuorum = spawnSync(process.execPath, [path.join(installedRoot, 'bin', 'aml.js'),
    'verify-signed-quorum', 'inflated-quorum.json'], { cwd: tempRoot, encoding: 'utf8' });
  if (rejectedQuorum.status !== 2 ||
      JSON.parse(rejectedQuorum.stdout).reason !== 'AML_SIGNED_QUORUM_MISMATCH') {
    throw new Error('Installed-package signed quorum CLI accepted an inflated summary');
  }

  const report = {
    protocol: 'aml-consumer-compatibility-report/1',
    package: pkg.name,
    version: pkg.version,
    platform: process.platform,
    architecture: process.arch,
    node: process.version,
    npm_pack: {
      filename: packResult.filename,
      integrity: packResult.integrity || null,
      shasum: packResult.shasum || null,
      size: packResult.size || null
    },
    checks: {
      clean_tarball_install: true,
      javascript_api_import: true,
      exported_symbol_count: Number(apiOutput),
      signed_http_gate_exported: true,
      aml_doctor: doctorOutput.length > 0,
      aml_cli_validate: /VALID:/i.test(validateOutput),
      consumer_quickstart_api: true,
      consumer_quickstart_cli: true,
      browser_witness_cli_valid: true,
      browser_witness_cli_rejects_other_challenge: true,
      signed_quorum_cli_valid: true,
      signed_quorum_cli_rejects_inflation: true,
      signed_quorum_cli_held_policy_valid: true,
      signed_quorum_cli_rejects_untrusted_key: true,
      consumer_receipt_sha256: quickstart.receipt_sha256
    },
    claim_boundary: matrix.claim_boundary
  };

  if (!report.checks.aml_doctor || !report.checks.aml_cli_validate) {
    throw new Error('Installed-package doctor or CLI validation did not produce the expected success signal');
  }

  process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
} finally {
  if (tarballPath && fs.existsSync(tarballPath)) fs.rmSync(tarballPath, { force: true });
  fs.rmSync(tempRoot, { recursive: true, force: true });
}
