#!/usr/bin/env node

import fs from "node:fs";
import { verifyGovernanceDisclosureAgainstSignedCommitment } from "../protocol/governanceDisclosureSignature.js";

function value(name) {
  const index = process.argv.indexOf(name);
  return index >= 0 ? process.argv[index + 1] ?? null : null;
}
function list(name) {
  const raw = value(name);
  return raw ? raw.split(",").map(v => v.trim()).filter(Boolean) : [];
}

const disclosurePath = process.argv[2];
const signedPath = process.argv[3];
if (!disclosurePath || !signedPath) {
  console.error("Usage: aml-governance-disclosure-signed-verify <disclosure.json> <signed-commitment.json> [--trusted-fingerprints a,b] [--revoked-fingerprints a,b] [--require-trusted-key] [--required-scope scope]");
  process.exit(1);
}

try {
  const disclosure = JSON.parse(fs.readFileSync(disclosurePath, "utf8"));
  const signed = JSON.parse(fs.readFileSync(signedPath, "utf8"));
  const result = verifyGovernanceDisclosureAgainstSignedCommitment(disclosure, signed, {
    trusted_fingerprints: list("--trusted-fingerprints"),
    revoked_fingerprints: list("--revoked-fingerprints"),
    require_trusted_key: process.argv.includes("--require-trusted-key"),
    required_scope: value("--required-scope") || undefined
  });
  process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
  process.exitCode = result.valid ? 0 : 2;
} catch (error) {
  process.stderr.write(`${error.message || error}\n`);
  process.exitCode = 1;
}
