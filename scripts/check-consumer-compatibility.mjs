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
import { createSignedVerificationQuorum,
  fingerprintVerifierPublicKey } from '../docs/aml-signed-verification-quorum.js';

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
  const verifierKeyB = await createVerifierKeyPair();
  const signedB = await signVerificationReport(reportB, verifierKeyB);
  const signedQuorum = await createSignedVerificationQuorum([signedA, signedB], { threshold: 2 });
  fs.writeFileSync(path.join(tempRoot, 'signed-quorum.json'), `${JSON.stringify(signedQuorum)}\n`);
  const quorumValid = JSON.parse(runNpm(['exec', '--', 'aml', 'verify-signed-quorum', 'signed-quorum.json'], tempRoot));
  if (!quorumValid.valid || !quorumValid.threshold_met) {
    throw new Error('Installed-package signed quorum CLI did not verify the saved threshold');
  }
  const paddedSigned = { ...signedB, signature: `${signedB.signature}==` };
  const paddedQuorum = await createSignedVerificationQuorum([signedA, paddedSigned], { threshold: 2 });
  fs.writeFileSync(path.join(tempRoot, 'padded-quorum.json'), `${JSON.stringify(paddedQuorum)}\n`);
  const paddedRun = spawnSync(process.execPath, [path.join(installedRoot, 'bin', 'aml.js'),
    'verify-signed-quorum', 'padded-quorum.json'], { cwd: tempRoot, encoding: 'utf8' });
  const paddedResult = JSON.parse(paddedRun.stdout);
  if (paddedRun.status !== 2 || !paddedResult.valid || paddedResult.threshold_met !== false ||
      paddedResult.quorum.summary.disagreement_reasons[0] !==
        'AML_SIGNED_REPORT_SIGNATURE_ENCODING_INVALID') {
    throw new Error('Installed-package signed quorum CLI accepted padded report signature');
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
  fs.writeFileSync(path.join(tempRoot, 'ambiguous-held-policy.json'),
    `${JSON.stringify(heldPolicy).replace('"prototype":true',
      String.raw`"prot\u006ftype":false,"prototype":true`)}\n`);
  const ambiguousPolicyRun = spawnSync(process.execPath, [path.join(installedRoot, 'bin', 'aml.js'),
    'verify-signed-quorum', 'signed-quorum.json', '--policy', 'ambiguous-held-policy.json'],
  { cwd: tempRoot, encoding: 'utf8' });
  if (ambiguousPolicyRun.status !== 1 || ambiguousPolicyRun.stdout ||
      !ambiguousPolicyRun.stderr.includes('duplicate JSON object key')) {
    throw new Error('Installed-package signed quorum CLI accepted an ambiguous held policy');
  }
  const groupPolicy = {
    schema: 'aml-signed-quorum-held-policy/2', prototype: true,
    artifact_type: signedQuorum.artifact_type, artifact_hash: signedQuorum.artifact_hash,
    trusted_keys: [
      { verifier_key_fingerprint: signedA.verifier_key_fingerprint, trust_group: 'lab-a' },
      { verifier_key_fingerprint: signedB.verifier_key_fingerprint, trust_group: 'lab-b' }
    ],
    threshold: 2, group_threshold: 2
  };
  fs.writeFileSync(path.join(tempRoot, 'group-policy.json'), `${JSON.stringify(groupPolicy)}\n`);
  const groupBound = JSON.parse(runNpm(['exec', '--', 'aml', 'verify-signed-quorum',
    'signed-quorum.json', '--policy', 'group-policy.json'], tempRoot));
  if (!groupBound.policy_met || groupBound.policy_evaluation.distinct_trust_groups !== 2) {
    throw new Error('Installed-package signed quorum CLI did not enforce held trust groups');
  }
  fs.writeFileSync(path.join(tempRoot, 'verifier-a.json'),
    `${JSON.stringify(signedA.verifier_public_key_jwk)}\n`);
  fs.writeFileSync(path.join(tempRoot, 'verifier-b.json'),
    `${JSON.stringify(signedB.verifier_public_key_jwk)}\n`);
  const keyA = JSON.parse(runNpm(['exec', '--', 'aml', 'fingerprint-verifier-key',
    'verifier-a.json'], tempRoot));
  const keyB = JSON.parse(runNpm(['exec', '--', 'aml', 'fingerprint-verifier-key',
    'verifier-b.json'], tempRoot));
  if (keyA.verifier_key_fingerprint !== signedA.verifier_key_fingerprint ||
      keyB.verifier_key_fingerprint !== signedB.verifier_key_fingerprint ||
      !/^[a-f0-9]{64}$/.test(keyA.key_material_fingerprint) ||
      !/^[a-f0-9]{64}$/.test(keyB.key_material_fingerprint)) {
    throw new Error('Installed-package key fingerprint command produced incorrect identifiers');
  }
  const materialPolicy = { ...groupPolicy, schema: 'aml-signed-quorum-held-policy/3',
    trusted_keys: [{ ...keyA, trust_group: 'lab-a' }, { ...keyB, trust_group: 'lab-b' }]
  };
  fs.writeFileSync(path.join(tempRoot, 'material-policy.json'), `${JSON.stringify(materialPolicy)}\n`);
  const materialBound = JSON.parse(runNpm(['exec', '--', 'aml', 'verify-signed-quorum',
    'signed-quorum.json', '--policy', 'material-policy.json'], tempRoot));
  if (!materialBound.policy_met || materialBound.policy_evaluation.distinct_trust_groups !== 2) {
    throw new Error('Installed-package signed quorum CLI did not enforce material pins');
  }
  const wrongMaterialPolicy = { ...materialPolicy, trusted_keys: [materialPolicy.trusted_keys[0],
    { ...materialPolicy.trusted_keys[1], key_material_fingerprint: '0'.repeat(64) }] };
  fs.writeFileSync(path.join(tempRoot, 'wrong-material-policy.json'),
    `${JSON.stringify(wrongMaterialPolicy)}\n`);
  const wrongMaterialRun = spawnSync(process.execPath, [path.join(installedRoot, 'bin', 'aml.js'),
    'verify-signed-quorum', 'signed-quorum.json', '--policy', 'wrong-material-policy.json'],
  { cwd: tempRoot, encoding: 'utf8' });
  const wrongMaterial = JSON.parse(wrongMaterialRun.stdout);
  if (wrongMaterialRun.status !== 2 || !wrongMaterial.valid || !wrongMaterial.threshold_met ||
      wrongMaterial.policy_met !== false ||
      wrongMaterial.policy_evaluation.mismatched_key_fingerprints[0] !== signedB.verifier_key_fingerprint) {
    throw new Error('Installed-package signed quorum CLI accepted a mismatched material pin');
  }
  const collapsedPolicy = { ...groupPolicy, trusted_keys: [
    groupPolicy.trusted_keys[0],
    { verifier_key_fingerprint: signedB.verifier_key_fingerprint, trust_group: 'lab-a' },
    { verifier_key_fingerprint: '0'.repeat(64), trust_group: 'lab-b' }
  ] };
  fs.writeFileSync(path.join(tempRoot, 'collapsed-policy.json'), `${JSON.stringify(collapsedPolicy)}\n`);
  const collapsedRun = spawnSync(process.execPath, [path.join(installedRoot, 'bin', 'aml.js'),
    'verify-signed-quorum', 'signed-quorum.json', '--policy', 'collapsed-policy.json'],
  { cwd: tempRoot, encoding: 'utf8' });
  const collapsed = JSON.parse(collapsedRun.stdout);
  if (collapsedRun.status !== 2 || !collapsed.valid || !collapsed.threshold_met ||
      collapsed.policy_met !== false || collapsed.policy_evaluation.distinct_trust_groups !== 1) {
    throw new Error('Installed-package signed quorum CLI accepted one trust group as two');
  }
  const witnessBound = JSON.parse(runNpm(['exec', '--', 'aml', 'verify-signed-quorum',
    'signed-quorum.json', '--policy', 'held-policy.json', '--bundle', 'witness.json',
    '--challenge', 'held-challenge.json'], tempRoot));
  if (!witnessBound.valid || !witnessBound.threshold_met ||
      !witnessBound.policy_met || !witnessBound.witness_met ||
      !witnessBound.replayable_claims_consistent) {
    throw new Error('Installed-package signed quorum CLI did not recheck the retained witness');
  }
  const completePolicy = { ...materialPolicy, schema: 'aml-signed-quorum-held-policy/4',
    require_complete_witness_claims: true };
  fs.writeFileSync(path.join(tempRoot, 'complete-policy.json'),
    `${JSON.stringify(completePolicy)}\n`);
  const completeBound = JSON.parse(runNpm(['exec', '--', 'aml', 'verify-signed-quorum',
    'signed-quorum.json', '--policy', 'complete-policy.json', '--bundle', 'witness.json',
    '--challenge', 'held-challenge.json'], tempRoot));
  if (!completeBound.policy_met || !completeBound.witness_met ||
      !completeBound.policy_evaluation.complete_claims_checked ||
      completeBound.policy_evaluation.unsatisfied_claims.length) {
    throw new Error('Installed-package signed quorum CLI did not require complete signed claims');
  }
  const vetoPolicy = { ...completePolicy, schema: 'aml-signed-quorum-held-policy/5',
    reject_trusted_dissent: true };
  fs.writeFileSync(path.join(tempRoot, 'veto-policy.json'), `${JSON.stringify(vetoPolicy)}\n`);
  const noDissent = JSON.parse(runNpm(['exec', '--', 'aml', 'verify-signed-quorum',
    'signed-quorum.json', '--policy', 'veto-policy.json', '--bundle', 'witness.json',
    '--challenge', 'held-challenge.json'], tempRoot));
  if (!noDissent.policy_met || noDissent.policy_evaluation.trusted_dissent.length) {
    throw new Error('Installed-package signed quorum CLI rejected a dissent-free held policy');
  }
  const signedDissent = await signVerificationReport({
    ...reportB, valid: false, reason: 'AML_TEST_SIGNED_DISSENT'
  }, verifierKeyB);
  const dissentQuorum = await createSignedVerificationQuorum(
    [signedA, signedB, signedDissent], { threshold: 2 });
  fs.writeFileSync(path.join(tempRoot, 'dissent-quorum.json'), `${JSON.stringify(dissentQuorum)}\n`);
  const dissentRun = spawnSync(process.execPath, [path.join(installedRoot, 'bin', 'aml.js'),
    'verify-signed-quorum', 'dissent-quorum.json', '--policy', 'veto-policy.json',
    '--bundle', 'witness.json', '--challenge', 'held-challenge.json'],
  { cwd: tempRoot, encoding: 'utf8' });
  const dissentResult = JSON.parse(dissentRun.stdout);
  if (dissentRun.status !== 2 || !dissentResult.valid || !dissentResult.threshold_met ||
      !dissentResult.witness_met || !dissentResult.replayable_claims_consistent ||
      dissentResult.policy_met !== false ||
      dissentResult.policy_evaluation.trusted_dissent[0]?.report_index !== 2) {
    throw new Error('Installed-package signed quorum CLI accepted trusted signed dissent');
  }
  const sparseSigned = await signVerificationReport({ ...reportA, checks: {} },
    await createVerifierKeyPair());
  const sparseQuorum = await createSignedVerificationQuorum([sparseSigned, signedB], { threshold: 2 });
  fs.writeFileSync(path.join(tempRoot, 'sparse-quorum.json'), `${JSON.stringify(sparseQuorum)}\n`);
  const sparsePolicy = { ...completePolicy, trusted_keys: [
    { ...await fingerprintVerifierPublicKey(sparseSigned.verifier_public_key_jwk), trust_group: 'lab-a' },
    completePolicy.trusted_keys[1]
  ] };
  fs.writeFileSync(path.join(tempRoot, 'sparse-policy.json'), `${JSON.stringify(sparsePolicy)}\n`);
  const sparseRun = spawnSync(process.execPath, [path.join(installedRoot, 'bin', 'aml.js'),
    'verify-signed-quorum', 'sparse-quorum.json', '--policy', 'sparse-policy.json',
    '--bundle', 'witness.json', '--challenge', 'held-challenge.json'],
  { cwd: tempRoot, encoding: 'utf8' });
  const sparseResult = JSON.parse(sparseRun.stdout);
  if (sparseRun.status !== 2 || !sparseResult.valid || !sparseResult.threshold_met ||
      !sparseResult.witness_met || !sparseResult.replayable_claims_consistent ||
      sparseResult.policy_met !== false ||
      sparseResult.policy_evaluation.unsatisfied_claims[0]?.report_index !== 0) {
    throw new Error('Installed-package signed quorum CLI accepted omitted signed checks');
  }
  const conflictingReport = { ...reportA, session_key_fingerprint: '0'.repeat(64) };
  const conflictingSigned = await signVerificationReport(conflictingReport, await createVerifierKeyPair());
  const conflictingQuorum = await createSignedVerificationQuorum([conflictingSigned, signedB], { threshold: 2 });
  fs.writeFileSync(path.join(tempRoot, 'conflicting-quorum.json'), `${JSON.stringify(conflictingQuorum)}\n`);
  const conflictingPolicy = { ...heldPolicy,
    trusted_key_fingerprints: [conflictingSigned.verifier_key_fingerprint, signedB.verifier_key_fingerprint]
  };
  fs.writeFileSync(path.join(tempRoot, 'conflicting-policy.json'), `${JSON.stringify(conflictingPolicy)}\n`);
  const conflictingResult = spawnSync(process.execPath, [path.join(installedRoot, 'bin', 'aml.js'),
    'verify-signed-quorum', 'conflicting-quorum.json', '--policy', 'conflicting-policy.json',
    '--bundle', 'witness.json', '--challenge', 'held-challenge.json'],
  { cwd: tempRoot, encoding: 'utf8' });
  const conflict = JSON.parse(conflictingResult.stdout);
  if (conflictingResult.status !== 2 || !conflict.valid || !conflict.threshold_met ||
      !conflict.policy_met || !conflict.witness_met || conflict.replayable_claims_consistent !== false) {
    throw new Error('Installed-package signed quorum CLI accepted contradictory signed witness claims');
  }
  const wrongWitness = spawnSync(process.execPath, [path.join(installedRoot, 'bin', 'aml.js'),
    'verify-signed-quorum', 'signed-quorum.json', '--bundle', 'witness.json',
    '--challenge', 'other-challenge.json'], { cwd: tempRoot, encoding: 'utf8' });
  const wrongWitnessResult = JSON.parse(wrongWitness.stdout);
  if (wrongWitness.status !== 2 || !wrongWitnessResult.valid ||
      !wrongWitnessResult.threshold_met || wrongWitnessResult.witness_met !== false) {
    throw new Error('Installed-package signed quorum CLI accepted a different retained challenge');
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
      signed_quorum_cli_rejects_noncanonical_signature: true,
      signed_quorum_cli_rejects_inflation: true,
      signed_quorum_cli_held_policy_valid: true,
      signed_quorum_cli_rejects_duplicate_json_key: true,
      signed_quorum_cli_group_policy_valid: true,
      signed_quorum_cli_material_policy_valid: true,
      signed_quorum_cli_rejects_wrong_material_pin: true,
      signed_quorum_cli_rejects_one_trust_group: true,
      signed_quorum_cli_rejects_untrusted_key: true,
      signed_quorum_cli_held_witness_valid: true,
      signed_quorum_cli_complete_claims_valid: true,
      signed_quorum_cli_trusted_dissent_veto_valid: true,
      signed_quorum_cli_rejects_omitted_signed_checks: true,
      signed_quorum_cli_rejects_conflicting_claims: true,
      signed_quorum_cli_rejects_other_witness_challenge: true,
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
