#!/usr/bin/env node

// bin/aml.js
// ĀML_CORE — Command-Line Interface

import fs from "fs";
import { compileAML, compileSource } from "../compiler/compiler.js";
import { generateAMLFromIntent } from "../compiler/intentCompiler.js";
import { simulatePolicies } from "../compiler/policySimulator.js";
import {
  executeAccountableIntent,
  verifyExecutionReceipt,
  signExecutionReceipt,
  verifySignedExecutionReceipt
} from "../compiler/accountablePipeline.js";
import { analyzeAMT } from "../compiler/diagnostics.js";
import { explainCompilation } from "../compiler/explain.js";
import { verifyBuildManifest } from "../compiler/verifyBuild.js";
import { signBuildManifest, verifyBuildAttestation } from "../compiler/signature.js";
import { listPolicies } from "../runtime/policyEngine.js";
import { listPolicyProfiles } from "../runtime/policyProfiles.js";

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
  aml verify-receipt <receipt.json>
  aml sign-receipt <receipt.json> <private-key.pem> [signed-receipt.json]
  aml verify-signed-receipt <signed-receipt.json>
  aml simulate <file.aml> [policy1,policy2]
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
  compile                 Compile AML into HTML and accountability artifacts
  generate                Deterministically generate AML source from machine-readable intent JSON
  execute                 Run intent → AML → simulations → composed policy → accountable receipt
  verify-receipt          Verify that an accountable execution receipt has not been mutated
  sign-receipt            Add an Ed25519 attestation to a valid execution receipt
  verify-signed-receipt   Verify receipt integrity, signature, and public-key fingerprint
  simulate                Compare identical AML meaning under multiple policy engines
  policies                List built-in policy engines
  profiles                List built-in user/organization policy profiles
  inspect                 Print the Abstract Meaning Tree + raw render decisions
  explain                 Print a compact explanation of decisions and diagnostics
  validate                Parse and evaluate AML without writing output files
  lint                    Run semantic diagnostics on meaning-bearing nodes
  verify                  Recompute SHA-256 digests and verify an AML build bundle
  sign                    Create a detached Ed25519 build attestation
  verify-attestation      Verify an Ed25519 AML build attestation
  help                    Show this help message
  version                 Show AML CLI version

Examples:
  aml compile examples/transmission-061.aml
  aml generate examples/intent-checkout.json generated.aml
  aml execute examples/intent-checkout.json privacy_first context.json receipt.json
  aml verify-receipt receipt.json
  aml sign-receipt receipt.json private-key.pem signed-receipt.json
  aml verify-signed-receipt signed-receipt.json
  aml simulate examples/simple.aml restorative_v1,attention_conservative_v1
  aml policies
  aml profiles
  aml explain examples/ai_assistant_response.aml
  aml lint examples/ethical_ads.aml
  aml verify dist/build_manifest.json
  aml sign dist/build_manifest.json private-key.pem dist/attestation.json
  aml verify-attestation dist/attestation.json dist/build_manifest.json
`);
}

function showVersion() {
  console.log("ĀML CLI v1.2.0-dev");
}

function readSource(filePath) {
  return fs.readFileSync(filePath, "utf8");
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
    const source = generateAMLFromIntent(intent);
    const outputPath = args[2];
    if (outputPath) {
      fs.writeFileSync(outputPath, source);
      console.log(`GENERATED: ${outputPath}`);
    } else {
      process.stdout.write(source);
    }
    process.exit(0);
  }

  if (command === "execute") {
    const intent = JSON.parse(readSource(inputPath));
    const profile = args[2] || "calm_default";
    const context = args[3] ? JSON.parse(readSource(args[3])) : {};
    const receipt = executeAccountableIntent(intent, { profile, context });
    const serialized = `${JSON.stringify(receipt, null, 2)}\n`;
    const outputPath = args[4];
    if (outputPath) {
      fs.writeFileSync(outputPath, serialized);
      console.log(`EXECUTED: ${outputPath}`);
      console.log(`Receipt SHA-256: ${receipt.receipt_sha256}`);
    } else {
      process.stdout.write(serialized);
    }
    process.exit(0);
  }

  if (command === "verify-receipt") {
    const receipt = JSON.parse(readSource(inputPath));
    const result = verifyExecutionReceipt(receipt);
    console.log(JSON.stringify(result, null, 2));
    process.exit(result.verified ? 0 : 1);
  }

  if (command === "sign-receipt") {
    const privateKeyPath = args[2];
    if (!privateKeyPath) throw new Error("A private key PEM path is required.");
    const receipt = JSON.parse(readSource(inputPath));
    const signed = signExecutionReceipt(receipt, readSource(privateKeyPath), {
      signer: process.env.AML_SIGNER || null
    });
    const outputPath = args[3];
    const serialized = `${JSON.stringify(signed, null, 2)}\n`;
    if (outputPath) {
      fs.writeFileSync(outputPath, serialized);
      console.log(`SIGNED RECEIPT: ${outputPath}`);
    } else {
      process.stdout.write(serialized);
    }
    process.exit(0);
  }

  if (command === "verify-signed-receipt") {
    const receipt = JSON.parse(readSource(inputPath));
    const result = verifySignedExecutionReceipt(receipt);
    console.log(JSON.stringify(result, null, 2));
    process.exit(result.verified ? 0 : 1);
  }

  if (command === "simulate") {
    const policies = (args[2] || "restorative_v1,attention_conservative_v1").split(",").map(item => item.trim()).filter(Boolean);
    const result = simulatePolicies(readSource(inputPath), policies);
    console.log(JSON.stringify({ input: inputPath, ...result }, null, 2));
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

    if (diagnostics.length === 0) {
      console.log(`CLEAN: ${inputPath}`);
    } else {
      for (const item of diagnostics) {
        console.log(`${item.level.toUpperCase()} ${item.code}: ${item.message} [${item.identifier || item.name || item.node_type}]`);
      }
    }

    console.log(`Errors: ${errors.length}`);
    console.log(`Warnings: ${warnings.length}`);
    process.exit(errors.length > 0 ? 1 : 0);
  }

  if (command === "verify") {
    const result = verifyBuildManifest(inputPath);
    for (const check of result.checks) {
      console.log(`${check.ok ? "PASS" : "FAIL"} ${check.kind}: ${check.file} — ${check.reason}`);
    }
    console.log(`Verified: ${result.verified}`);
    console.log(`Passed: ${result.passed}`);
    console.log(`Failed: ${result.failed}`);
    process.exit(result.verified ? 0 : 1);
  }

  if (command === "sign") {
    const privateKeyPath = args[2];
    if (!privateKeyPath) throw new Error("A private key PEM path is required.");
    const attestation = signBuildManifest(inputPath, readSource(privateKeyPath), { signer: process.env.AML_SIGNER || null });
    const outputPath = args[3];
    const serialized = `${JSON.stringify(attestation, null, 2)}\n`;
    if (outputPath) {
      fs.writeFileSync(outputPath, serialized);
      console.log(`SIGNED: ${outputPath}`);
    } else {
      process.stdout.write(serialized);
    }
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
  console.error(error.message);
  process.exit(1);
}
