#!/usr/bin/env node

import fs from "node:fs";
import path from "node:path";
import { meaningFingerprint, compareMeaningFingerprints } from "../compiler/meaningFingerprint.js";
import { createMeaningManifest, verifyMeaningManifest } from "../compiler/meaningManifest.js";
import { signMeaningManifest, verifySignedMeaningManifest } from "../compiler/meaningManifestAttestation.js";

const args = process.argv.slice(2);

function usage() {
  console.error("Usage:");
  console.error("  aml-meaning <file.aml> [other.aml]");
  console.error("  aml-meaning manifest <file.aml> [more.aml ...]");
  console.error("  aml-meaning verify-manifest <manifest.json>");
  console.error("  aml-meaning sign-manifest <manifest.json> <private-key.pem> [signer]");
  console.error("  aml-meaning verify-attestation <attestation.json> <manifest.json>");
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
    console.log(JSON.stringify(report, null, 2));
    process.exit(report.verified ? 0 : 1);
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
    console.log(JSON.stringify(report, null, 2));
    process.exit(report.verified ? 0 : 1);
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
