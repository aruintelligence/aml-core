#!/usr/bin/env node

import fs from "node:fs";
import path from "node:path";
import { meaningFingerprint, compareMeaningFingerprints } from "../compiler/meaningFingerprint.js";
import { createMeaningManifest, verifyMeaningManifest } from "../compiler/meaningManifest.js";
import { signMeaningManifest, verifySignedMeaningManifest } from "../compiler/meaningManifestAttestation.js";
import { decideCommand, diagnosticOnlyRequested, pinMatches, takeOption, AML_DIAGNOSTIC_ONLY_FLAG } from "../runtime/commandAuthorization.js";

// Directive 010: `verified` is a precondition, never permission.
// verify-manifest authorizes only when --expected-root-sha256 pins the
// manifest root; verify-attestation only when --trusted-key-sha256 pins the
// signing key. Fingerprint comparison (exit 0 = equivalent) is a comparison of
// two caller files, not a trust decision, and is unchanged.
const DENIALS = { verified: "AML_AUTHZ_NOT_VERIFIED", root_pinned: "AML_AUTHZ_MANIFEST_ROOT_NOT_PINNED",
  signing_key_pinned: "AML_AUTHZ_SIGNING_KEY_NOT_PINNED" };
const diagnosticOnly = diagnosticOnlyRequested(process.argv);
let args = process.argv.slice(2).filter(arg => arg !== AML_DIAGNOSTIC_ONLY_FLAG);
const pins = {};
for (const flag of ["--expected-root-sha256", "--trusted-key-sha256"]) {
  try {
    const taken = takeOption(args, flag);
    pins[flag] = taken.value;
    args = taken.rest;
  } catch (error) {
    console.error(error.message);
    process.exit(2);
  }
}

function finish(report, pinName, pinned, trust) {
  const verified = report?.verified === true;
  const { output, exitCode } = decideCommand(report, {
    consistent: verified, conditions: { verified, [pinName]: verified && pinned === true },
    required: ["verified", pinName], denials: DENIALS,
    trust: [...trust, "a key fingerprint binds a key, not a real-world identity"], diagnosticOnly, invalidCode: 1
  });
  console.log(JSON.stringify(output, null, 2));
  process.exit(exitCode);
}

function usage() {
  console.error("Usage:");
  console.error("  aml-meaning <file.aml> [other.aml]");
  console.error("  aml-meaning manifest <file.aml> [more.aml ...]");
  console.error("  aml-meaning verify-manifest <manifest.json> [--expected-root-sha256 HEX] [--diagnostic-only]");
  console.error("  aml-meaning sign-manifest <manifest.json> <private-key.pem> [signer]");
  console.error("  aml-meaning verify-attestation <attestation.json> <manifest.json> [--trusted-key-sha256 HEX] [--diagnostic-only]");
  console.error("  verify-*: exit 0 authorized, 3 verified but not authorized (no matching pin), 1 not verified, 2 usage/error");
}

function portableRelativePath(inputPath) {
  const absolute = path.resolve(inputPath);
  const relative = path.relative(process.cwd(), absolute);
  if (!relative || relative === ".." || relative.startsWith(`..${path.sep}`) || path.isAbsolute(relative)) {
    throw new Error(`Manifest input must resolve inside the current working directory: ${inputPath}`);
  }
  return relative.split(path.sep).join("/");
}

function safeManifestReadPath(value) {
  if (typeof value !== "string" || !value || value.includes("\\") || value.startsWith("/") || /^[A-Za-z]:\//.test(value)) {
    throw new Error(`Unsafe Meaning Manifest path: ${String(value)}`);
  }
  const segments = value.split("/");
  if (segments.some(segment => !segment || segment === "." || segment === "..")) throw new Error(`Unsafe Meaning Manifest path: ${value}`);
  return path.resolve(process.cwd(), ...segments);
}

if (args.length === 0) { usage(); process.exit(2); }

try {
  if (args[0] === "manifest") {
    const files = args.slice(1);
    if (!files.length) throw new Error("manifest requires at least one AML file.");
    const sources = Object.fromEntries(files.map(file => [portableRelativePath(file), fs.readFileSync(file, "utf8")]));
    console.log(JSON.stringify(createMeaningManifest(sources), null, 2));
    process.exit(0);
  }

  if (args[0] === "verify-manifest") {
    const manifestPath = args[1];
    if (!manifestPath || args.length !== 2) throw new Error("verify-manifest requires exactly one manifest JSON path.");
    const manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8"));
    if (!Array.isArray(manifest.files)) throw new Error("Meaning Manifest files must be an array.");
    const sources = Object.fromEntries(manifest.files.map(file => [file.path, fs.readFileSync(safeManifestReadPath(file.path), "utf8")]));
    const report = verifyMeaningManifest(manifest, sources);
    finish(report, "root_pinned", pinMatches(pins["--expected-root-sha256"], manifest.root_sha256),
      ["the --expected-root-sha256 value came from an independently trusted source"]);
  }

  if (args[0] === "sign-manifest") {
    const [, manifestPath, keyPath, signer] = args;
    if (!manifestPath || !keyPath || args.length > 4) throw new Error("sign-manifest requires <manifest.json> <private-key.pem> [signer].");
    const manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8"));
    const privateKey = fs.readFileSync(keyPath, "utf8");
    console.log(JSON.stringify(signMeaningManifest(manifest, privateKey, { signer: signer ?? null }), null, 2));
    process.exit(0);
  }

  if (args[0] === "verify-attestation") {
    const [, attestationPath, manifestPath] = args;
    if (!attestationPath || !manifestPath || args.length !== 3) throw new Error("verify-attestation requires <attestation.json> <manifest.json>.");
    const attestation = JSON.parse(fs.readFileSync(attestationPath, "utf8"));
    const manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8"));
    const report = verifySignedMeaningManifest(attestation, manifest);
    finish(report, "signing_key_pinned", report.public_key_fingerprint_valid === true &&
      pinMatches(pins["--trusted-key-sha256"], attestation.public_key_sha256),
      ["the --trusted-key-sha256 value came from an independently trusted source"]);
  }

  const [leftPath, rightPath, ...rest] = args;
  if (rest.length) throw new Error("Fingerprint comparison accepts at most two AML files.");
  const leftSource = fs.readFileSync(leftPath, "utf8");
  if (!rightPath) {
    console.log(JSON.stringify({ file: leftPath, ...meaningFingerprint(leftSource) }, null, 2));
    process.exit(0);
  }
  const rightSource = fs.readFileSync(rightPath, "utf8");
  const report = compareMeaningFingerprints(leftSource, rightSource);
  console.log(JSON.stringify({ left_file: leftPath, right_file: rightPath, ...report }, null, 2));
  process.exit(report.equivalent ? 0 : 1);
} catch (error) {
  console.error(error instanceof Error ? error.message : String(error));
  process.exit(2);
}
