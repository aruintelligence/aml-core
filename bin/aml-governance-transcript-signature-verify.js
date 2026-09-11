#!/usr/bin/env node

import fs from "node:fs";
import { verifySignedGovernanceStreamTranscript } from "../protocol/governanceTranscriptSignature.js";

function values(name) {
  const result = [];
  for (let index = 0; index < process.argv.length; index += 1) {
    if (process.argv[index] === name && process.argv[index + 1]) result.push(process.argv[index + 1]);
  }
  return result;
}

function value(name, fallback = null) {
  const index = process.argv.indexOf(name);
  return index >= 0 ? process.argv[index + 1] ?? fallback : fallback;
}

const signedPath = process.argv[2];
if (!signedPath) {
  console.error("Usage: aml-governance-transcript-signature-verify <signed.json> [--trusted-fingerprint sha256hex ...] [--require-trusted-key] [--expected-key-id id]");
  process.exit(1);
}

try {
  const signed = JSON.parse(fs.readFileSync(signedPath, "utf8"));
  const verification = verifySignedGovernanceStreamTranscript(signed, {
    trusted_fingerprints: values("--trusted-fingerprint"),
    require_trusted_key: process.argv.includes("--require-trusted-key"),
    expected_key_id: value("--expected-key-id") || undefined
  });
  process.stdout.write(`${JSON.stringify(verification, null, 2)}\n`);
  if (!verification.valid) process.exitCode = 2;
} catch (error) {
  process.stderr.write(`${error.message || error}\n`);
  process.exitCode = 1;
}
