#!/usr/bin/env node

// bin/aml.js
// ĀML_CORE — Command-Line Interface

import fs from "fs";
import { webcrypto } from "node:crypto";
import { compileAML, compileSource } from "../compiler/compiler.js";
import { generateAMLFromIntent } from "../compiler/intentCompiler.js";
import { simulatePolicies } from "../compiler/policySimulator.js";
import { semanticDiff } from "../compiler/semanticDiff.js";
import { policyDiff } from "../compiler/policyDiff.js";
import {
  executeAccountableIntent,
  verifyExecutionReceipt,
  replayExecutionReceipt,
  signExecutionReceipt,
  verifySignedExecutionReceipt
} from "../compiler/accountablePipeline.js";
import { analyzeAMT } from "../compiler/diagnostics.js";
import { explainCompilation } from "../compiler/explain.js";
import { verifyBuildManifest } from "../compiler/verifyBuild.js";
import { signBuildManifest, verifyBuildAttestation } from "../compiler/signature.js";
import { listPolicies } from "../runtime/policyEngine.js";
import { listPolicyProfiles } from "../runtime/policyProfiles.js";
import { signPolicyPack, verifySignedPolicyPack } from "../runtime/policyPack.js";
import { verifyAuditStream } from "../runtime/auditStream.js";
import { enforceCumulativeAttentionBudget } from "../runtime/attentionLedger.js";
import { signBrandAuthorization, verifyBrandAuthorization } from "../runtime/brandAuthorization.js";
import { createDeploymentFirewall } from "../runtime/deploymentFirewall.js";
import { evaluatePolicyCanary } from "../runtime/policyCanary.js";
import { verifyWitnessBundle } from "../docs/aml-witness-bundle.js";
import { assertBrowserJSON, canonicalJSONStringifyBrowser, sha256Browser } from "../docs/aml-browser-integrity.js";
import { fingerprintVerifierPublicKey, verifySignedVerificationQuorum } from "../docs/aml-signed-verification-quorum.js";
import { parseJsonWithoutDuplicateKeys } from "../runtime/strictJson.js";

const args = process.argv.slice(2);
const command = args[0];
const inputPath = args[1] || "examples/transmission-061.aml";
const outputDir = args[2] || "dist";

function showHelp() {
  console.log(`
ĀML — ĀRU Meaning Language

Usage:
  aml compile <file.aml> [outputDir]
  aml generate <intent.json> [output.aml]
  aml execute <intent.json> [profile] [context.json] [receipt.json]
  aml deploy <intent.json> [--mode shadow|enforce] [--profile profile] [--failure-mode open|closed] [--context context.json] [--timestamp ISO] [--require-effective-allow]
  aml canary <intent.json> [--baseline profile] [--candidate profile] [--context context.json] [--timestamp ISO] [--fail-on-change]
  aml verify-receipt <receipt.json>
  aml verify-witness <bundle.json> <verifier-held-challenge.json>
  aml fingerprint-verifier-key <public-jwk.json>
  aml fingerprint-json <input.json>
  aml verify-signed-quorum <quorum.json> [--policy held-policy.json] [--bundle witness.json --challenge held-challenge.json] [--expect-inputs held-inputs.json] [--portable] [--decision-only]
  aml replay-receipt <receipt.json>
  aml sign-receipt <receipt.json> <private-key.pem> [signed-receipt.json]
  aml verify-signed-receipt <signed-receipt.json>
  aml simulate <file.aml> [policy1,policy2]
  aml semantic-diff <left.aml> <right.aml>
  aml policy-diff <file.aml> <left-policy-or-profile> <right-policy-or-profile> [context.json]
  aml sign-policy-pack <pack.json> <private-key.pem> [signed-pack.json]
  aml verify-policy-pack <signed-pack.json>
  aml sign-brand-authorization <authorization.json> <private-key.pem> [credential.json]
  aml verify-brand-authorization <credential.json> [revocation-registry.json]
  aml verify-audit <audit-stream.json>
  aml attention-account <file.aml> <budget> [policy]
  aml policies
  aml profiles
  aml inspect <file.aml>
  aml explain <file.aml>
  aml validate <file.aml>
  aml lint <file.aml>
  aml verify <build_manifest.json>
  aml sign <build_manifest.json> <private-key.pem> [attestation.json]
  aml verify-attestation <attestation.json> [build_manifest.json]
  aml help
  aml version

Commands:
  compile                     Compile AML into HTML and accountability artifacts
  generate                    Deterministically generate AML source from machine-readable intent JSON
  execute                     Run intent → AML → simulations → policy profile → audit/attention receipt
  deploy                      Evaluate intent with enforce/shadow rollout and explicit failure posture
  canary                      Compare the same intent under baseline and candidate policy profiles
  verify-receipt              Verify receipt hash, audit stream, and attention-ledger integrity
  verify-witness              Verify a browser witness bundle against your retained challenge
  fingerprint-verifier-key    Derive full-JWK and P-256 material fingerprints from a public key
  fingerprint-json            Hash a strict JSON input under sorted-json-v1
  verify-signed-quorum        Recheck a signed quorum; --decision-only omits supplied report contents
  replay-receipt              Re-execute declared receipt inputs with the installed engine
  sign-receipt                Add an Ed25519 attestation to a valid execution receipt
  verify-signed-receipt       Verify receipt integrity, signature, and public-key fingerprint
  simulate                    Compare identical AML meaning under multiple policy engines
  semantic-diff               Compare Abstract Meaning Trees instead of raw text lines
  policy-diff                 Show which render decisions change between policies/profiles
  sign-policy-pack            Sign a data-only policy pack with Ed25519
  verify-policy-pack          Verify policy-pack hash, signature, and key fingerprint
  sign-brand-authorization    Sign a scoped official-brand authorization credential with Ed25519
  verify-brand-authorization  Verify brand credential integrity, expiry, and optional revocation status
  verify-audit                Verify a SHA-256 hash-chained runtime audit stream
  attention-account           Apply cumulative session attention accounting to render decisions
  policies                    List built-in policy engines
  profiles                    List built-in user/organization policy profiles
  inspect                     Print the Abstract Meaning Tree + raw render decisions
  explain                     Print a compact explanation of decisions and diagnostics
  validate                    Parse and evaluate AML without writing output files
  lint                        Run semantic diagnostics on meaning-bearing nodes
  verify                      Recompute SHA-256 digests and verify an AML build bundle
  sign                        Create a detached Ed25519 build attestation
  verify-attestation          Verify an Ed25519 AML build attestation
  help                        Show this help message
  version                     Show AML CLI version

Examples:
  aml deploy examples/intent-checkout.json --mode shadow --profile calm_default
  aml deploy examples/intent-checkout.json --mode enforce --failure-mode closed --require-effective-allow
  aml canary examples/intent-checkout.json --baseline calm_default --candidate human_first --fail-on-change
  aml semantic-diff before.aml after.aml
  aml policy-diff examples/simple.aml restorative_v1 attention_conservative_v1
  aml sign-policy-pack policy-pack.json private-key.pem signed-policy-pack.json
  aml verify-policy-pack signed-policy-pack.json
  aml sign-brand-authorization authorization.json aru-private-key.pem brand-credential.json
  aml verify-brand-authorization brand-credential.json revocation-registry.json
  aml attention-account examples/simple.aml 10 restorative_v1
  aml execute examples/intent-checkout.json human_first context.json receipt.json
  aml verify-receipt receipt.json
  aml verify-witness bundle.json my-challenge.json
  aml verify-signed-quorum saved-quorum.json
  aml replay-receipt receipt.json
`);
}

function showVersion() {
  console.log("ĀML CLI v1.3.0");
}

function readSource(filePath) {
  return fs.readFileSync(filePath, "utf8");
}

function readUnambiguousJSON(filePath, options) {
  const source = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true })
    .decode(fs.readFileSync(filePath));
  return parseJsonWithoutDuplicateKeys(source, options);
}

// A small, unsigned log record derived only from verifier-computed booleans,
// input hashes, and the local replay instant. Never copy a supplied report,
// artifact label, signer name, note, or error string into this projection.
function signedQuorumDecisionOnly(result) {
  const names = new Set(['valid', 'threshold_met', 'portable_met', 'policy_met',
    'witness_met', 'replayable_claims_consistent', 'inputs_met']);
  const checked = result.requested_conditions.checked;
  if (!Array.isArray(checked) || checked.some(name => !names.has(name) ||
      typeof result[name] !== 'boolean')) throw new Error('AML_SIGNED_QUORUM_DECISION_INVALID');
  const unmet = checked.filter(name => result[name] !== true);
  if (result.requested_conditions_met !== (unmet.length === 0)) {
    throw new Error('AML_SIGNED_QUORUM_DECISION_INVALID');
  }
  const decision = {
    schema: 'aml-signed-quorum-decision/1', prototype: true,
    ...Object.fromEntries(checked.map(name => [name, result[name]])),
    requested_conditions_met: unmet.length === 0,
    requested_conditions: { checked, unmet }
  };
  if (result.input_fingerprints) {
    const input = result.input_fingerprints;
    if (input.canonicalization !== 'sorted-json-v1') throw new Error('AML_SIGNED_QUORUM_DECISION_INVALID');
    decision.input_fingerprints = { canonicalization: 'sorted-json-v1' };
    for (const name of ['quorum_sha256', 'policy_sha256', 'witness_bundle_sha256',
      'held_challenge_sha256']) {
      if (Object.hasOwn(input, name)) {
        if (!/^[a-f0-9]{64}$/.test(input[name])) throw new Error('AML_SIGNED_QUORUM_DECISION_INVALID');
        decision.input_fingerprints[name] = input[name];
      }
    }
  }
  if (result.input_evaluation) {
    const hash = result.input_evaluation.expectations_sha256;
    if (!/^[a-f0-9]{64}$/.test(hash)) throw new Error('AML_SIGNED_QUORUM_DECISION_INVALID');
    decision.expectations_sha256 = hash;
  }
  if (result.witness_evaluation) {
    const { evaluated_at, clock_source } = result.witness_evaluation;
    if (typeof evaluated_at !== 'string' || !/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/.test(evaluated_at) ||
        clock_source !== 'local_system') throw new Error('AML_SIGNED_QUORUM_DECISION_INVALID');
    decision.witness_evaluated_at = evaluated_at;
    decision.witness_clock_source = clock_source;
  }
  return decision;
}

function writeOrPrint(value, outputPath, label = "WROTE") {
  const serialized = typeof value === "string" ? value : `${JSON.stringify(value, null, 2)}\n`;
  if (outputPath) {
    fs.writeFileSync(outputPath, serialized);
    console.log(`${label}: ${outputPath}`);
  } else {
    process.stdout.write(serialized);
  }
}

function flagValue(name, fallback = null) {
  const index = args.indexOf(name);
  if (index < 0) return fallback;
  const value = args[index + 1];
  if (!value || value.startsWith("--")) throw new Error(`${name} requires a value.`);
  return value;
}

function hasFlag(name) {
  return args.includes(name);
}

try {
  if (!command || command === "help" || command === "--help" || command === "-h") {
    showHelp();
    process.exit(0);
  }
  if (command === "version" || command === "--version" || command === "-v") {
    showVersion();
    process.exit(0);
  }
  if (command === "policies") {
    console.log(JSON.stringify(listPolicies(), null, 2));
    process.exit(0);
  }
  if (command === "profiles") {
    console.log(JSON.stringify(listPolicyProfiles(), null, 2));
    process.exit(0);
  }
  if (command === "compile") {
    const result = compileAML(inputPath, outputDir);
    console.log("ĀML compile complete.");
    console.log(`Input: ${result.input}`);
    console.log(`Output: ${result.output}`);
    console.log(`Tokens: ${result.tokens.length}`);
    console.log(`Render decisions: ${result.renderDecisions.length}`);
    console.log(`Manifest: ${outputDir}/build_manifest.json`);
    process.exit(0);
  }
  if (command === "generate") {
    const intent = JSON.parse(readSource(inputPath));
    writeOrPrint(generateAMLFromIntent(intent), args[2], "GENERATED");
    process.exit(0);
  }
  if (command === "execute") {
    const intent = JSON.parse(readSource(inputPath));
    const profile = args[2] || "calm_default";
    const context = args[3] ? JSON.parse(readSource(args[3])) : {};
    const receipt = executeAccountableIntent(intent, { profile, context });
    writeOrPrint(receipt, args[4], "EXECUTED");
    if (args[4]) console.log(`Receipt SHA-256: ${receipt.receipt_sha256}`);
    process.exit(0);
  }
  if (command === "deploy") {
    const intent = JSON.parse(readSource(inputPath));
    const mode = flagValue("--mode", "shadow");
    const profile = flagValue("--profile", "human_first");
    const failureMode = flagValue("--failure-mode", "closed");
    const contextPath = flagValue("--context", null);
    const context = contextPath ? JSON.parse(readSource(contextPath)) : {};
    const timestamp = flagValue("--timestamp", process.env.AML_TIMESTAMP || undefined);
    const result = createDeploymentFirewall({ mode, profile, failure_mode: failureMode, context }).evaluate(intent, {
      mode,
      profile,
      failure_mode: failureMode,
      context,
      timestamp
    });
    console.log(JSON.stringify(result, null, 2));
    if (result.evaluation_error) process.exit(2);
    if (hasFlag("--require-effective-allow") && !result.effective_allowed) process.exit(3);
    process.exit(0);
  }
  if (command === "canary") {
    const intent = JSON.parse(readSource(inputPath));
    const baseline = flagValue("--baseline", "calm_default");
    const candidate = flagValue("--candidate", "human_first");
    const contextPath = flagValue("--context", null);
    const context = contextPath ? JSON.parse(readSource(contextPath)) : {};
    const timestamp = flagValue("--timestamp", process.env.AML_TIMESTAMP || undefined);
    const result = evaluatePolicyCanary(intent, {
      baseline_profile: baseline,
      candidate_profile: candidate,
      context,
      timestamp
    });
    console.log(JSON.stringify(result, null, 2));
    if (hasFlag("--fail-on-change") && result.changed_decisions > 0) process.exit(4);
    process.exit(0);
  }
  if (command === "verify-receipt") {
    const result = verifyExecutionReceipt(JSON.parse(readSource(inputPath)));
    console.log(JSON.stringify(result, null, 2));
    process.exit(result.verified ? 0 : 1);
  }
  if (command === "verify-witness") {
    if (args.length !== 3 || !args[1] || !args[2]) {
      throw new Error("Usage: aml verify-witness <bundle.json> <verifier-held-challenge.json>");
    }
    // Support Node builds that do not expose Web Crypto on globalThis.
    if (!globalThis.crypto?.subtle) globalThis.crypto = webcrypto;
    const bundle = readUnambiguousJSON(args[1]);
    const expectedChallenge = readUnambiguousJSON(args[2]);
    const result = await verifyWitnessBundle(bundle, { expectedChallenge });
    console.log(JSON.stringify(result, null, 2));
    process.exit(result.valid ? 0 : 2);
  }
  if (command === "fingerprint-verifier-key") {
    if (args.length !== 2 || !args[1]) {
      throw new Error("Usage: aml fingerprint-verifier-key <public-jwk.json>");
    }
    if (!globalThis.crypto?.subtle) globalThis.crypto = webcrypto;
    const fingerprints = await fingerprintVerifierPublicKey(readUnambiguousJSON(args[1]));
    console.log(JSON.stringify(fingerprints, null, 2));
    process.exit(0);
  }
  if (command === "fingerprint-json") {
    if (args.length !== 2 || !args[1]) throw new Error("Usage: aml fingerprint-json <input.json>");
    if (!globalThis.crypto?.subtle) globalThis.crypto = webcrypto;
    const value = readUnambiguousJSON(args[1]);
    assertBrowserJSON(value);
    console.log(JSON.stringify({ canonicalization: 'sorted-json-v1',
      sha256: await sha256Browser(canonicalJSONStringifyBrowser(value)) }, null, 2));
    process.exit(0);
  }
  if (command === "verify-signed-quorum") {
    const usage = "Usage: aml verify-signed-quorum <quorum.json> [--policy held-policy.json] [--bundle witness.json --challenge held-challenge.json] [--expect-inputs held-inputs.json] [--portable] [--decision-only]";
    if (!args[1] || args[1].startsWith('--')) throw new Error(usage);
    const options = new Map();
    let portable = false;
    let decisionOnly = false;
    for (let index = 2; index < args.length;) {
      const flag = args[index];
      if (flag === '--portable') {
        if (portable) throw new Error(usage);
        portable = true;
        index += 1;
        continue;
      }
      if (flag === '--decision-only') {
        if (decisionOnly) throw new Error(usage);
        decisionOnly = true;
        index += 1;
        continue;
      }
      const value = args[index + 1];
      if (!['--policy', '--bundle', '--challenge', '--expect-inputs'].includes(flag) || !value ||
          value.startsWith('--') || options.has(flag)) throw new Error(usage);
      options.set(flag, value);
      index += 2;
    }
    if (options.has('--bundle') !== options.has('--challenge')) throw new Error(usage);
    if (!globalThis.crypto?.subtle) globalThis.crypto = webcrypto;
    const parseOptions = { integerNumbersOnly: portable };
    const policy = options.has('--policy') ? readUnambiguousJSON(options.get('--policy'), parseOptions) : undefined;
    const witnessBundle = options.has('--bundle') ? readUnambiguousJSON(options.get('--bundle'), parseOptions) : undefined;
    const expectedChallenge = options.has('--challenge') ? readUnambiguousJSON(options.get('--challenge'), parseOptions) : undefined;
    const expectedInputFingerprints = options.has('--expect-inputs')
      ? readUnambiguousJSON(options.get('--expect-inputs'), parseOptions) : undefined;
    const result = await verifySignedVerificationQuorum(readUnambiguousJSON(args[1], parseOptions), {
      policy, witnessBundle, expectedChallenge, expectedInputFingerprints, portable
    });
    // A saved quorum can produce more JSON than a pipe can buffer. Wait for
    // stdout to finish writing before exiting with the verification status.
    await new Promise((resolve, reject) => {
      process.stdout.write(`${JSON.stringify(decisionOnly ? signedQuorumDecisionOnly(result) : result, null, 2)}\n`, error =>
        error ? reject(error) : resolve());
    });
    process.exit(result.requested_conditions_met ? 0 : 2);
  }
  if (command === "replay-receipt") {
    const result = replayExecutionReceipt(JSON.parse(readSource(inputPath)));
    console.log(JSON.stringify(result, null, 2));
    process.exit(result.verified ? 0 : 1);
  }
  if (command === "sign-receipt") {
    const privateKeyPath = args[2];
    if (!privateKeyPath) throw new Error("A private key PEM path is required.");
    const signed = signExecutionReceipt(JSON.parse(readSource(inputPath)), readSource(privateKeyPath), { signer: process.env.AML_SIGNER || null });
    writeOrPrint(signed, args[3], "SIGNED RECEIPT");
    process.exit(0);
  }
  if (command === "verify-signed-receipt") {
    const result = verifySignedExecutionReceipt(JSON.parse(readSource(inputPath)));
    console.log(JSON.stringify(result, null, 2));
    process.exit(result.verified ? 0 : 1);
  }
  if (command === "simulate") {
    const policies = (args[2] || "restorative_v1,attention_conservative_v1").split(",").map(item => item.trim()).filter(Boolean);
    console.log(JSON.stringify({ input: inputPath, ...simulatePolicies(readSource(inputPath), policies) }, null, 2));
    process.exit(0);
  }
  if (command === "semantic-diff") {
    const rightPath = args[2];
    if (!rightPath) throw new Error("A second AML file is required.");
    console.log(JSON.stringify(semanticDiff(readSource(inputPath), readSource(rightPath)), null, 2));
    process.exit(0);
  }
  if (command === "policy-diff") {
    const leftTarget = args[2];
    const rightTarget = args[3];
    if (!leftTarget || !rightTarget) throw new Error("Both left and right policy/profile targets are required.");
    const context = args[4] ? JSON.parse(readSource(args[4])) : {};
    console.log(JSON.stringify(policyDiff(readSource(inputPath), leftTarget, rightTarget, { context }), null, 2));
    process.exit(0);
  }
  if (command === "sign-policy-pack") {
    const privateKeyPath = args[2];
    if (!privateKeyPath) throw new Error("A private key PEM path is required.");
    const signed = signPolicyPack(JSON.parse(readSource(inputPath)), readSource(privateKeyPath), { signer: process.env.AML_SIGNER || null });
    writeOrPrint(signed, args[3], "SIGNED POLICY PACK");
    process.exit(0);
  }
  if (command === "verify-policy-pack") {
    const result = verifySignedPolicyPack(JSON.parse(readSource(inputPath)));
    console.log(JSON.stringify(result, null, 2));
    process.exit(result.verified ? 0 : 1);
  }
  if (command === "sign-brand-authorization") {
    const privateKeyPath = args[2];
    if (!privateKeyPath) throw new Error("A private key PEM path is required.");
    const request = JSON.parse(readSource(inputPath));
    const credential = signBrandAuthorization(request, readSource(privateKeyPath), {
      issuer: process.env.AML_BRAND_ISSUER || "ĀRU Intelligence Inc."
    });
    writeOrPrint(credential, args[3], "SIGNED BRAND AUTHORIZATION");
    if (args[3]) console.log(`Credential SHA-256: ${credential.credential_hash}`);
    process.exit(0);
  }
  if (command === "verify-brand-authorization") {
    const credential = JSON.parse(readSource(inputPath));
    const revocationRegistry = args[2] ? JSON.parse(readSource(args[2])) : null;
    const result = verifyBrandAuthorization(credential, {
      now: process.env.AML_VERIFY_AT || null,
      revocation_registry: revocationRegistry,
      expected_issuer: process.env.AML_EXPECTED_BRAND_ISSUER || null
    });
    console.log(JSON.stringify(result, null, 2));
    process.exit(result.valid ? 0 : 1);
  }
  if (command === "verify-audit") {
    const result = verifyAuditStream(JSON.parse(readSource(inputPath)));
    console.log(JSON.stringify(result, null, 2));
    process.exit(result.verified ? 0 : 1);
  }
  if (command === "attention-account") {
    const budget = Number(args[2]);
    if (!Number.isFinite(budget) || budget < 0) throw new Error("A non-negative numeric budget is required.");
    const policy = args[3] || "restorative_v1";
    const compiled = compileSource(readSource(inputPath), { policy, timestamp: "1970-01-01T00:00:00.000Z" });
    const result = enforceCumulativeAttentionBudget(compiled.renderDecisions, budget);
    console.log(JSON.stringify(result, null, 2));
    process.exit(0);
  }
  if (command === "inspect") {
    const result = compileSource(readSource(inputPath));
    console.log(JSON.stringify({ input: inputPath, amt: result.amt, render_decisions: result.renderDecisions }, null, 2));
    process.exit(0);
  }
  if (command === "explain") {
    const result = compileSource(readSource(inputPath), { timestamp: "1970-01-01T00:00:00.000Z" });
    console.log(JSON.stringify({ input: inputPath, ...explainCompilation(result) }, null, 2));
    process.exit(0);
  }
  if (command === "validate") {
    const result = compileSource(readSource(inputPath));
    console.log(`VALID: ${inputPath}`);
    console.log(`Tokens: ${result.tokens.length}`);
    console.log(`Render decisions: ${result.renderDecisions.length}`);
    process.exit(0);
  }
  if (command === "lint") {
    const result = compileSource(readSource(inputPath), { timestamp: "1970-01-01T00:00:00.000Z" });
    const diagnostics = analyzeAMT(result.amt);
    const errors = diagnostics.filter(item => item.level === "error");
    const warnings = diagnostics.filter(item => item.level === "warning");
    if (diagnostics.length === 0) console.log(`CLEAN: ${inputPath}`);
    else for (const item of diagnostics) console.log(`${item.level.toUpperCase()} ${item.code}: ${item.message} [${item.identifier || item.name || item.node_type}]`);
    console.log(`Errors: ${errors.length}`);
    console.log(`Warnings: ${warnings.length}`);
    process.exit(errors.length > 0 ? 1 : 0);
  }
  if (command === "verify") {
    const result = verifyBuildManifest(inputPath);
    for (const check of result.checks) console.log(`${check.ok ? "PASS" : "FAIL"} ${check.kind}: ${check.file} — ${check.reason}`);
    console.log(`Verified: ${result.verified}`);
    console.log(`Passed: ${result.passed}`);
    console.log(`Failed: ${result.failed}`);
    process.exit(result.verified ? 0 : 1);
  }
  if (command === "sign") {
    const privateKeyPath = args[2];
    if (!privateKeyPath) throw new Error("A private key PEM path is required.");
    const attestation = signBuildManifest(inputPath, readSource(privateKeyPath), { signer: process.env.AML_SIGNER || null });
    writeOrPrint(attestation, args[3], "SIGNED");
    process.exit(0);
  }
  if (command === "verify-attestation") {
    const attestation = JSON.parse(readSource(inputPath));
    const result = verifyBuildAttestation(attestation, args[2] || attestation.manifest_path);
    console.log(JSON.stringify(result, null, 2));
    process.exit(result.verified ? 0 : 1);
  }

  console.error(`Unknown command: ${command}`);
  showHelp();
  process.exit(1);
} catch (error) {
  console.error("ĀML command failed.");
  // Parser and filesystem errors can quote source text or paths. Compact
  // quorum mode must keep those off stderr as well as stdout.
  console.error(command === "verify-signed-quorum" && args.includes("--decision-only")
    ? "AML_SIGNED_QUORUM_INPUT_OR_USAGE_ERROR" : error.message);
  process.exit(1);
}
