#!/usr/bin/env node

// bin/aml.js
// ĀML_CORE — Command-Line Interface

import fs from "fs";
import { createHash, webcrypto } from "node:crypto";
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
import { listPolicyProfiles, policyProfileSha256 } from "../runtime/policyProfiles.js";
import { signPolicyPack, verifySignedPolicyPack } from "../runtime/policyPack.js";
import { verifyAuditStream } from "../runtime/auditStream.js";
import { enforceCumulativeAttentionBudget } from "../runtime/attentionLedger.js";
import { signBrandAuthorization, verifyBrandAuthorization } from "../runtime/brandAuthorization.js";
import { commandAuthorizationDecision, withCommandAuthorization, commandOutcome, trustedCommandClock, decideCommand,
  pinMatches, AML_DIAGNOSTIC_ONLY_FLAG, AML_EXIT_NOT_AUTHORIZED, AML_NOT_AN_AUTHORIZATION_DECISION } from "../runtime/commandAuthorization.js";
import { revocationRegistryFingerprint } from "../runtime/revocationRegistry.js";
import { evaluateTrustConfigAll, enrolledTrustStateDirs, trustConfigTrustsKey, trustConfigPinMatches,
  trustConfigRequiresSingleUse, initTrustState, signTrustConfig } from "../runtime/trustConfig.js";
import { openDurableConsumptionStore, consumptionKey } from "../runtime/consumptionStore.js";

// verify-brand-authorization authorizes only a valid credential whose issuer
// and signing-key fingerprint were pinned by the relying party, after a
// revocation registry was checked, evaluated on the verifier's own clock.
// AML_VERIFY_AT is a replay override: any caller-supplied time is untrusted
// and the result is not authorized. The revocation registry must match the
// relying party's pinned registry digest (AML_TRUSTED_REVOCATION_REGISTRY_SHA256);
// an unpinned registry could be an empty or rolled-back copy.
const BRAND_REQUIRED = ["credential_valid", "issuer_pinned", "signing_key_pinned", "revocation_checked", "revocation_registry_pinned", "trusted_clock"];
const BRAND_DENIALS = { credential_valid: "AML_AUTHZ_CREDENTIAL_NOT_VALID", issuer_pinned: "AML_AUTHZ_ISSUER_NOT_PINNED",
  signing_key_pinned: "AML_AUTHZ_SIGNING_KEY_NOT_PINNED", revocation_checked: "AML_AUTHZ_REVOCATION_NOT_CHECKED",
  revocation_registry_pinned: "AML_AUTHZ_REVOCATION_REGISTRY_NOT_PINNED",
  trusted_clock: "AML_AUTHZ_CALLER_CLOCK_UNTRUSTED" };
const BRAND_TRUST = ["the pinned issuer and key fingerprint came from an independently trusted source",
  "the pinned revocation registry digest is current (a pin cannot prove freshness)", "the verifier host clock",
  "a key fingerprint binds a key, not a real-world identity"];

// Verifier commands whose only check is integrity or a signature by an
// embedded key. Each authorizes only when the relying party pinned the
// artifact digest or the signing-key fingerprint out of band.
const VERIFY_DENIALS = {
  verified: "AML_AUTHZ_NOT_VERIFIED",
  artifact_pinned: "AML_AUTHZ_ARTIFACT_NOT_PINNED",
  signing_key_pinned: "AML_AUTHZ_SIGNING_KEY_NOT_PINNED",
  policy_allowed: "AML_AUTHZ_POLICY_DENIED",
  evaluation_ok: "AML_AUTHZ_EVALUATION_ERROR"
};
const PIN_TRUST = ["the pinned digest or key fingerprint came from an independently trusted source",
  "a key fingerprint binds a key, not a real-world identity"];
const PIN_FLAGS = new Set(["--expected-sha256", "--trusted-key-sha256", "--trust-config", "--trust-state", "--single-use-store"]);
const TRUST_DENIALS = {
  trust_config_trusted: "AML_AUTHZ_TRUST_CONFIG_NOT_TRUSTED",
  single_use_consumed: "AML_AUTHZ_ALREADY_CONSUMED",
  single_use_store_present: "AML_AUTHZ_SINGLE_USE_STORE_REQUIRED",
  policy_pinned: "AML_AUTHZ_POLICY_NOT_PINNED",
  profile_pinned: "AML_AUTHZ_PROFILE_NOT_PINNED",
  caller_timestamp_absent: "AML_AUTHZ_CALLER_CLOCK_UNTRUSTED"
};
const TRUST_CONFIG_TRUST = ["a threshold of root keys was not stolen and the trust anchor on this host was not replaced",
  "the local clock is not earlier than it should be (it is checked against the persisted time floor, not an external source)"];

// Trust-config mode (see runtime/trustConfig.js). Active when --trust-config
// is given or any trust state directory is enrolled: the root-owned system
// directory, $AML_TRUST_STATE_DIR, or --trust-state. On an enrolled host a
// command without --trust-config is not authorized; environment and flags can
// add an enrolled directory but cannot remove the system one.
function trustMode() {
  const configPath = flagValue("--trust-config", null);
  const dirs = enrolledTrustStateDirs([flagValue("--trust-state", null), process.env.AML_TRUST_STATE_DIR || null]);
  if (configPath === null && dirs.length === 0) return null;
  if (configPath === null) return { decision: null, dirs };
  const envelope = parseJsonWithoutDuplicateKeys(readSource(configPath));
  const callerTime = process.env.AML_VERIFY_AT || (hasFlag("--now") ? "caller" : null);
  return { decision: evaluateTrustConfigAll(envelope, { stateDirs: dirs, callerTime }), dirs };
}

function trustSummary(trust) {
  if (!trust) return { mode: "explicit-pins" };
  const d = trust.decision;
  return { mode: "trust-config", trusted: d?.trusted === true, reasons: d ? [...d.reasons] : ["trust_config_missing"],
    version: d?.version ?? null, config_sha256: d?.config_sha256 ?? null, expires_at: d?.expires_at ?? null };
}

// Single-use (opt-in with --single-use-store, mandatory when the trust config
// sets require_single_use). Consumed only after every other condition passed.
// An untrusted config is already denied by trust_config_trusted, so only a
// trusted config's own require_single_use adds the store requirement here.
function singleUse(trust, conditions, artifactId) {
  const storeDir = flagValue("--single-use-store", null);
  const configRequires = trust !== null && trust.decision?.trusted === true && trustConfigRequiresSingleUse(trust.decision);
  if (storeDir === null) return configRequires ? { required: true, name: "single_use_store_present", ok: false } : { required: false };
  let consumed = false;
  const othersOk = Object.values(conditions).every(v => v === true);
  if (othersOk && typeof artifactId === "string" && /^[a-f0-9]{64}$/.test(artifactId)) {
    try {
      consumed = openDurableConsumptionStore(storeDir).consume(consumptionKey(["cli-verifier", command, artifactId]),
        { purpose: "cli-verifier", command, artifact_sha256: artifactId });
    } catch { consumed = false; }
  }
  return { required: true, name: "single_use_consumed", ok: consumed };
}

// verify-witness / verify-signed-quorum compute their own decision; in
// trust-config mode (or with a single-use store) that decision is ANDed with
// trust_config_trusted and single use. Never ORed: a false base stays false.
const TRUST_FLAGS = new Set(["--trust-config", "--trust-state", "--single-use-store"]);
function withoutTrustFlags(list) {
  const out = [];
  for (let index = 0; index < list.length; index += 1) {
    if (TRUST_FLAGS.has(list[index])) {
      const value = list[index + 1];
      if (!value || value.startsWith("--")) throw new Error(`${list[index]} requires exactly one value`);
      index += 1;
      continue;
    }
    out.push(list[index]);
  }
  return out;
}
function trustGate(result, artifactId, diagnosticOnly) {
  const base = result?.authorized === true && result?.authorization?.authorized === true;
  const trust = trustMode();
  if (trust === null && flagValue("--single-use-store", null) === null) return { result, authorized: base };
  const conditions = { verifier_decision_allowed: base };
  if (trust !== null) conditions.trust_config_trusted = trust.decision?.trusted === true;
  const once = diagnosticOnly ? { required: false } : singleUse(trust, conditions, artifactId);
  if (once.required) conditions[once.name] = once.ok;
  const authorized = !diagnosticOnly && Object.values(conditions).every(v => v === true);
  const added = Object.keys(conditions).filter(name => conditions[name] !== true && TRUST_DENIALS[name]).map(name => TRUST_DENIALS[name]);
  const prior = Array.isArray(result?.authorization?.reasons) ? result.authorization.reasons.filter(r => r !== "AML_AUTHZ_ALLOW") : [];
  const authorization = authorized ? result.authorization : { ...(result?.authorization ?? {}), authorized: false, decision: "deny",
    reasons: [...new Set([...prior, ...added])],
    required: [...new Set([...(result?.authorization?.required ?? []), ...Object.keys(conditions).filter(n => n !== "verifier_decision_allowed")])] };
  return { result: { ...result, authorized, authorization, ...(trust ? { trust: trustSummary(trust) } : {}),
    ...(once.required ? { single_use: { consumed: conditions[once.name] === true } } : {}) }, authorized };
}

// Positional arguments without the authorization flags and their values.
function positionalArgs() {
  const out = [];
  for (let index = 0; index < args.length; index += 1) {
    if (PIN_FLAGS.has(args[index])) { index += 1; continue; }
    if (args[index] === AML_DIAGNOSTIC_ONLY_FLAG) continue;
    out.push(args[index]);
  }
  return out;
}

function finishVerification(verification, { pinKind, pinActual, extra = {}, extraRequired = [], role = null, artifactId = null }) {
  const pinName = pinKind === "key" ? "signing_key_pinned" : "artifact_pinned";
  const pin = flagValue(pinKind === "key" ? "--trusted-key-sha256" : "--expected-sha256", null);
  const required = ["verified", pinName, ...extraRequired];
  const trust = trustMode();
  let pinOk = pinMatches(pin, pinActual);
  const conditions = { verified: verification?.verified === true, ...extra };
  if (trust !== null) {
    // In trust-config mode a key must be trusted by the config for this
    // command's role; an explicit flag pin, if also given, must match too.
    if (pinKind === "key") pinOk = (pin === null || pinOk) && trustConfigTrustsKey(trust.decision, pinActual, role);
    conditions.trust_config_trusted = trust.decision?.trusted === true;
    required.push("trust_config_trusted");
    if (role === "policy-pack" && trust.decision?.trusted === true && trust.decision.effective.policy_sha256 !== null) {
      conditions.policy_pinned = trustConfigPinMatches(trust.decision, "policy_sha256", verification?.pack_sha256);
      required.push("policy_pinned");
    }
  }
  conditions[pinName] = pinOk;
  const once = singleUse(trust, conditions, verification?.verified === true ? artifactId : null);
  if (once.required) { conditions[once.name] = once.ok; required.push(once.name); }
  const { output, exitCode } = decideCommand(trust ? { ...verification, trust: trustSummary(trust) } : verification, {
    consistent: verification?.verified === true,
    conditions,
    required, denials: { ...VERIFY_DENIALS, ...TRUST_DENIALS }, trust: trust ? [...PIN_TRUST, ...TRUST_CONFIG_TRUST] : PIN_TRUST,
    diagnosticOnly: hasFlag(AML_DIAGNOSTIC_ONLY_FLAG), invalidCode: 1
  });
  console.log(JSON.stringify(output, null, 2));
  process.exit(exitCode);
}

function sha256Hex(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}
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
  aml verify-signed-quorum <quorum.json> [--policy held-policy.json] [--bundle witness.json --challenge held-challenge.json] [--expect-inputs held-inputs.json] [--portable] [--decision-only] [--diagnostic-only]
  aml replay-receipt <receipt.json>
  aml sign-receipt <receipt.json> <private-key.pem> [signed-receipt.json]
  aml verify-signed-receipt <signed-receipt.json>
  aml simulate <file.aml> [policy1,policy2]
  aml semantic-diff <left.aml> <right.aml>
  aml policy-diff <file.aml> <left-policy-or-profile> <right-policy-or-profile> [context.json]
  aml sign-policy-pack <pack.json> <private-key.pem> [signed-pack.json]
  aml verify-policy-pack <signed-pack.json>
  aml sign-brand-authorization <authorization.json> <private-key.pem> [credential.json]
  aml verify-brand-authorization <credential.json> [revocation-registry.json] [--diagnostic-only]
  aml verify-audit <audit-stream.json>
  aml attention-account <file.aml> <budget> [policy]
  aml policies
  aml profiles
  aml inspect <file.aml>
  aml explain <file.aml>
  aml validate <file.aml>
  aml lint <file.aml>
  aml verify <build_manifest.json>
  aml trust-init <state-dir> --threshold N --root-key-sha256 <k1,k2,k3>
  aml trust-sign <config-body.json> <root1.pem,root2.pem> [envelope.json]
  aml trust-verify --trust-config <envelope.json> [--trust-state <dir>]
  aml profile-sha256 <profile>    digest for a trust config's profile_sha256 (enforced by deploy in trust-config mode)

  Verifier options (verify, verify-receipt, replay-receipt, verify-signed-receipt, verify-policy-pack,
  verify-attestation, verify-audit, verify-brand-authorization):
    --trust-config <envelope.json>  signed, versioned trust config (threshold root keys, rollback + expiry)
    --trust-state <dir>             enrolled trust state dir (also $AML_TRUST_STATE_DIR, /etc/aml/trust)
    --single-use-store <dir>        durable single-use store; the same artifact authorizes at most once
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
  verify-signed-quorum        Recheck a signed quorum; exit 0 only when authorized; --decision-only omits supplied report contents
  replay-receipt              Re-execute declared receipt inputs with the installed engine
  sign-receipt                Add an Ed25519 attestation to a valid execution receipt
  verify-signed-receipt       Verify receipt integrity, signature, and public-key fingerprint
  simulate                    Compare identical AML meaning under multiple policy engines
  semantic-diff               Compare Abstract Meaning Trees instead of raw text lines
  policy-diff                 Show which render decisions change between policies/profiles
  sign-policy-pack            Sign a data-only policy pack with Ed25519
  verify-policy-pack          Verify policy-pack hash, signature, and key fingerprint
  sign-brand-authorization    Sign a scoped official-brand authorization credential with Ed25519
  verify-brand-authorization  Verify brand credential; exit 0 only when authorized (pinned issuer/key, revocation, own clock)
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
    requested_conditions: { checked, unmet },
    // The complete decision; requested_conditions_met alone is not permission.
    authorized: result.authorized === true && result.authorization?.authorized === true,
    authorization_reasons: Array.isArray(result.authorization?.reasons)
      ? result.authorization.reasons.filter(reason => /^AML_AUTHZ_[A-Z_]+$/.test(reason)) : ['AML_AUTHZ_EVALUATION_ERROR']
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
    // Exit 0 only when the AML policy itself allowed the intent. Shadow mode
    // and failure_mode=open set effective_allowed for observability; neither
    // is authorization. --require-effective-allow is now the default and kept
    // as a no-op; --diagnostic-only exits 0 for any completed evaluation.
    const evaluated = !result.evaluation_error;
    const deployConditions = { evaluation_ok: evaluated, policy_allowed: evaluated && result.aml_allowed === true };
    const deployRequired = ["evaluation_ok", "policy_allowed"];
    const trust = trustMode();
    if (trust !== null) {
      // In trust-config mode the profile is not the invoker's choice: its
      // digest must equal the config's profile_sha256 (a null pin denies),
      // and a caller-chosen evaluation time is refused.
      let profileDigest = null;
      try { profileDigest = policyProfileSha256(profile); } catch { profileDigest = null; }
      deployConditions.trust_config_trusted = trust.decision?.trusted === true;
      deployConditions.profile_pinned = trustConfigPinMatches(trust.decision, "profile_sha256", profileDigest);
      deployConditions.caller_timestamp_absent = timestamp === undefined || timestamp === null;
      deployRequired.push("trust_config_trusted", "profile_pinned", "caller_timestamp_absent");
    }
    const deployArtifact = createHash("sha256").update(JSON.stringify({ intent, profile, mode, failureMode, context })).digest("hex");
    const deployOnce = singleUse(trust, deployConditions, deployArtifact);
    if (deployOnce.required) { deployConditions[deployOnce.name] = deployOnce.ok; deployRequired.push(deployOnce.name); }
    const { output, exitCode } = decideCommand(trust ? { ...result, trust: trustSummary(trust) } : result, {
      consistent: evaluated,
      conditions: deployConditions,
      required: deployRequired, denials: { ...VERIFY_DENIALS, ...TRUST_DENIALS },
      trust: ["the AML policy profile and context supplied to the evaluation are the intended ones",
        ...(trust ? TRUST_CONFIG_TRUST : [])],
      diagnosticOnly: hasFlag(AML_DIAGNOSTIC_ONLY_FLAG), invalidCode: 2
    });
    console.log(JSON.stringify(output, null, 2));
    process.exit(exitCode);
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
    const receipt = JSON.parse(readSource(positionalArgs()[1] || inputPath));
    const result = verifyExecutionReceipt(receipt);
    finishVerification(result, { pinKind: "artifact", pinActual: result.verified === true ? receipt?.receipt_sha256 : null,
      artifactId: receipt?.receipt_sha256 });
  }
  if (command === "verify-witness") {
    const witnessArgs = withoutTrustFlags(args);
    if (witnessArgs.length !== 3 || !witnessArgs[1] || !witnessArgs[2]) {
      throw new Error("Usage: aml verify-witness <bundle.json> <verifier-held-challenge.json> [--trust-config c.json] [--trust-state dir] [--single-use-store dir]");
    }
    // Support Node builds that do not expose Web Crypto on globalThis.
    if (!globalThis.crypto?.subtle) globalThis.crypto = webcrypto;
    const bundleBytes = fs.readFileSync(witnessArgs[1]);
    const bundle = readUnambiguousJSON(witnessArgs[1]);
    const expectedChallenge = readUnambiguousJSON(witnessArgs[2]);
    const verified = await verifyWitnessBundle(bundle, { expectedChallenge });
    // trustGate ANDs trust_config_trusted / single use into `authorized`.
    const result = trustGate(verified, sha256Hex(bundleBytes), false).result;
    console.log(JSON.stringify(result, null, 2));
    // `valid` is internal consistency only; exit 0 requires the explicit decision.
    process.exit(result.authorized === true ? 0 : 2);
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
    const usage = "Usage: aml verify-signed-quorum <quorum.json> [--policy held-policy.json] [--bundle witness.json --challenge held-challenge.json] [--expect-inputs held-inputs.json] [--portable] [--decision-only] [--diagnostic-only]";
    const quorumArgs = withoutTrustFlags(args);
    if (!quorumArgs[1] || quorumArgs[1].startsWith('--')) throw new Error(usage);
    const options = new Map();
    let portable = false;
    let decisionOnly = false;
    let diagnosticOnly = false;
    for (let index = 2; index < quorumArgs.length;) {
      const flag = quorumArgs[index];
      if (flag === '--portable') {
        if (portable) throw new Error(usage);
        portable = true;
        index += 1;
        continue;
      }
      if (flag === AML_DIAGNOSTIC_ONLY_FLAG) {
        if (diagnosticOnly) throw new Error(usage);
        diagnosticOnly = true;
        index += 1;
        continue;
      }
      if (flag === '--decision-only') {
        if (decisionOnly) throw new Error(usage);
        decisionOnly = true;
        index += 1;
        continue;
      }
      const value = quorumArgs[index + 1];
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
    const quorumBytes = fs.readFileSync(quorumArgs[1]);
    const quorumResult = await verifySignedVerificationQuorum(readUnambiguousJSON(quorumArgs[1], parseOptions), {
      policy, witnessBundle, expectedChallenge, expectedInputFingerprints, portable
    });
    // trustGate ANDs trust_config_trusted / single use into `authorized`.
    const result = trustGate(quorumResult, sha256Hex(quorumBytes), diagnosticOnly).result;
    // A saved quorum can produce more JSON than a pipe can buffer. Wait for
    // stdout to finish writing before exiting with the verification status.
    await new Promise((resolve, reject) => {
      const projected = decisionOnly ? signedQuorumDecisionOnly(result) : result;
      const printed = diagnosticOnly ? { ...projected, authorized: false, diagnostic_only: true,
        decision_use: AML_NOT_AN_AUTHORIZATION_DECISION } : projected;
      process.stdout.write(`${JSON.stringify(printed, null, 2)}\n`, error =>
        error ? reject(error) : resolve());
    });
    // Exit 0 only on the complete decision (`authorized`). Requested
    // conditions met without a held policy or witness requirement exits 3.
    if (diagnosticOnly) {
      process.exit(result.requested_conditions_met === true ? 0 : 2);
    }
    process.exit(result.authorized === true && result.authorization?.authorized === true ? 0
      : result.requested_conditions_met === true ? AML_EXIT_NOT_AUTHORIZED : 2);
  }
  if (command === "replay-receipt") {
    const receipt = JSON.parse(readSource(positionalArgs()[1] || inputPath));
    const result = replayExecutionReceipt(receipt);
    finishVerification(result, { pinKind: "artifact", pinActual: result.verified === true ? receipt?.receipt_sha256 : null,
      artifactId: receipt?.receipt_sha256 });
  }
  if (command === "sign-receipt") {
    const privateKeyPath = args[2];
    if (!privateKeyPath) throw new Error("A private key PEM path is required.");
    const signed = signExecutionReceipt(JSON.parse(readSource(inputPath)), readSource(privateKeyPath), { signer: process.env.AML_SIGNER || null });
    writeOrPrint(signed, args[3], "SIGNED RECEIPT");
    process.exit(0);
  }
  if (command === "verify-signed-receipt") {
    const receipt = JSON.parse(readSource(positionalArgs()[1] || inputPath));
    const result = verifySignedExecutionReceipt(receipt);
    finishVerification(result, { pinKind: "key",
      pinActual: result.verified === true && result.public_key_fingerprint_valid === true ? receipt?.signature?.public_key_sha256 : null,
      role: "receipt", artifactId: receipt?.receipt_sha256 });
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
    const pack = JSON.parse(readSource(positionalArgs()[1] || inputPath));
    const result = verifySignedPolicyPack(pack);
    finishVerification(result, { pinKind: "key",
      pinActual: result.verified === true && result.public_key_fingerprint_valid === true ? pack?.attestation?.public_key_sha256 : null,
      role: "policy-pack", artifactId: result.pack_sha256 });
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
    const positional = positionalArgs().slice(1);
    const diagnosticOnly = args.includes(AML_DIAGNOSTIC_ONLY_FLAG);
    const credential = JSON.parse(readSource(positional[0] || inputPath));
    const revocationRegistry = positional[1] ? JSON.parse(readSource(positional[1])) : null;
    const callerTime = process.env.AML_VERIFY_AT || null;
    const localNow = Date.now();
    const expectedIssuer = process.env.AML_EXPECTED_BRAND_ISSUER || null;
    const trustedKey = process.env.AML_TRUSTED_BRAND_KEY_SHA256 || null;
    const verification = verifyBrandAuthorization(credential, {
      now: callerTime,
      revocation_registry: revocationRegistry,
      expected_issuer: expectedIssuer
    });
    const brandConditions = {
      credential_valid: verification.valid === true,
      issuer_pinned: typeof expectedIssuer === "string" && verification.issuer === expectedIssuer,
      signing_key_pinned: typeof trustedKey === "string" && /^[a-f0-9]{64}$/.test(trustedKey) &&
        credential?.public_key_sha256 === trustedKey,
      revocation_checked: verification.credential_revocation_checked === true,
      revocation_registry_pinned: revocationRegistry !== null &&
        pinMatches(process.env.AML_TRUSTED_REVOCATION_REGISTRY_SHA256 || null, revocationRegistryFingerprint(revocationRegistry)),
      trusted_clock: trustedCommandClock(callerTime, localNow)
    };
    const brandRequired = [...BRAND_REQUIRED];
    const trust = trustMode();
    if (trust !== null) {
      // The signed config supplies the key and registry pins; env pins, when
      // also present, must match as well (AND, never OR).
      const registryDigest = revocationRegistry !== null ? revocationRegistryFingerprint(revocationRegistry) : null;
      const envKey = process.env.AML_TRUSTED_BRAND_KEY_SHA256 || null;
      const envRegistry = process.env.AML_TRUSTED_REVOCATION_REGISTRY_SHA256 || null;
      brandConditions.signing_key_pinned = (envKey === null || brandConditions.signing_key_pinned)
        && trustConfigTrustsKey(trust.decision, credential?.public_key_sha256, "brand-authorization");
      brandConditions.revocation_registry_pinned = revocationRegistry !== null
        && (envRegistry === null || pinMatches(envRegistry, registryDigest))
        && trustConfigPinMatches(trust.decision, "registry_sha256", registryDigest);
      brandConditions.trust_config_trusted = trust.decision?.trusted === true;
      brandRequired.push("trust_config_trusted");
    }
    // singleUse consumes only when every brand condition (credential_valid included) is true.
    const once = singleUse(trust, brandConditions, credential?.credential_hash);
    if (once.required) { brandConditions[once.name] = once.ok; brandRequired.push(once.name); }
    const result = withCommandAuthorization(trust ? { ...verification, trust: trustSummary(trust) } : verification,
      commandAuthorizationDecision(brandConditions, brandRequired, { ...BRAND_DENIALS, ...TRUST_DENIALS }),
      trust ? [...BRAND_TRUST, ...TRUST_CONFIG_TRUST] : BRAND_TRUST);
    const { output, exitCode } = commandOutcome(result, { diagnosticOnly, invalidCode: 1 });
    console.log(JSON.stringify(output, null, 2));
    process.exit(exitCode);
  }
  if (command === "verify-audit") {
    // The pin is the head entry hash; an empty stream has no head and never authorizes.
    const result = verifyAuditStream(JSON.parse(readSource(positionalArgs()[1] || inputPath)));
    finishVerification(result, { pinKind: "artifact", pinActual: result.verified === true ? result.head_hash : null,
      artifactId: result.head_hash });
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
  if (command === "profile-sha256") {
    // Digest to place in a trust config's profile_sha256.
    console.log(policyProfileSha256(args[1] || "human_first"));
    process.exit(0);
  }
  if (command === "trust-init") {
    // Enroll a trust state directory with the out-of-band root anchor.
    const dir = args[1];
    const threshold = Number(flagValue("--threshold", null));
    const keyids = (flagValue("--root-key-sha256", "") || "").split(",").map(v => v.trim()).filter(Boolean);
    if (!dir || dir.startsWith("--")) throw new Error("Usage: aml trust-init <state-dir> --threshold N --root-key-sha256 a,b,c");
    const anchor = initTrustState(dir, { threshold, rootKeyids: keyids });
    console.log(JSON.stringify({ enrolled: true, state_dir: dir, root: anchor.root }, null, 2));
    process.exit(0);
  }
  if (command === "trust-sign") {
    // aml trust-sign <config-body.json> <root-key.pem>[,<root-key.pem>...] [envelope.json]
    const body = parseJsonWithoutDuplicateKeys(readSource(args[1]));
    const pems = String(args[2] || "").split(",").filter(Boolean).map(file => readSource(file));
    if (pems.length === 0) throw new Error("At least one root private key PEM path is required.");
    writeOrPrint(signTrustConfig(body, pems), args[3], "SIGNED TRUST CONFIG");
    process.exit(0);
  }
  if (command === "trust-verify") {
    // Exit 0 only when the config is trusted by every enrolled state dir
    // (threshold, rollback, expiry on the local clock, persisted).
    const trust = trustMode();
    const decision = trust?.decision || null;
    const trusted = decision?.trusted === true;
    console.log(JSON.stringify({ ...trustSummary(trust), effective: trusted ? decision.effective : null,
      authorized: trusted, decision_use: trusted ? "trust-config" : AML_NOT_AN_AUTHORIZATION_DECISION }, null, 2));
    process.exit(decision?.trusted === true && decision.reasons.length === 0 ? 0 : AML_EXIT_NOT_AUTHORIZED); // trust-verify-decision
  }
  if (command === "verify") {
    // Text report kept; authorization needs --expected-sha256 equal to the
    // SHA-256 of the manifest file bytes (the manifest itself is untrusted).
    const manifestPath = positionalArgs()[1] || inputPath;
    const result = verifyBuildManifest(manifestPath);
    for (const check of result.checks) console.log(`${check.ok ? "PASS" : "FAIL"} ${check.kind}: ${check.file} — ${check.reason}`);
    console.log(`Verified: ${result.verified}`);
    console.log(`Passed: ${result.passed}`);
    console.log(`Failed: ${result.failed}`);
    const manifestSha256 = result.verified === true ? sha256Hex(fs.readFileSync(manifestPath)) : null;
    const verifyConditions = { verified: result.verified === true, artifact_pinned: pinMatches(flagValue("--expected-sha256", null), manifestSha256) };
    const verifyRequired = ["verified", "artifact_pinned"];
    const trust = trustMode();
    if (trust !== null) { verifyConditions.trust_config_trusted = trust.decision?.trusted === true; verifyRequired.push("trust_config_trusted"); }
    const once = singleUse(trust, verifyConditions, manifestSha256);
    if (once.required) { verifyConditions[once.name] = once.ok; verifyRequired.push(once.name); }
    const verifyBase = { verified: result.verified, manifest_sha256: manifestSha256 };
    const { output, exitCode } = decideCommand(trust ? { ...verifyBase, trust: trustSummary(trust) } : verifyBase, {
      consistent: result.verified === true,
      conditions: verifyConditions,
      required: verifyRequired, denials: { ...VERIFY_DENIALS, ...TRUST_DENIALS }, trust: trust ? [...PIN_TRUST, ...TRUST_CONFIG_TRUST] : PIN_TRUST,
      diagnosticOnly: hasFlag(AML_DIAGNOSTIC_ONLY_FLAG), invalidCode: 1
    });
    console.log(`Authorized: ${output.authorized}`);
    console.log(`Authorization reasons: ${output.authorization.reasons.join(", ")}`);
    console.log(`Decision use: ${output.decision_use}`);
    process.exit(exitCode);
  }
  if (command === "sign") {
    const privateKeyPath = args[2];
    if (!privateKeyPath) throw new Error("A private key PEM path is required.");
    const attestation = signBuildManifest(inputPath, readSource(privateKeyPath), { signer: process.env.AML_SIGNER || null });
    writeOrPrint(attestation, args[3], "SIGNED");
    process.exit(0);
  }
  if (command === "verify-attestation") {
    const positional = positionalArgs();
    const attestation = JSON.parse(readSource(positional[1] || inputPath));
    const result = verifyBuildAttestation(attestation, positional[2] || attestation.manifest_path);
    finishVerification(result, { pinKind: "key",
      pinActual: result.verified === true && result.public_key_fingerprint_valid === true ? attestation?.public_key_sha256 : null,
      role: "build-attestation", artifactId: result.manifest_sha256 });
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
