#!/usr/bin/env node

import fs from "node:fs";
import { verifyGovernanceDisclosure } from "../protocol/governanceDisclosure.js";

function value(name) {
  const index = process.argv.indexOf(name);
  return index >= 0 ? process.argv[index + 1] ?? null : null;
}

const disclosurePath = process.argv[2];
if (!disclosurePath) {
  console.error("Usage: aml-governance-disclosure-verify <disclosure.json> [--expected-merkle-root sha256] [--expected-transcript-root sha256]");
  process.exit(1);
}

try {
  const disclosure = JSON.parse(fs.readFileSync(disclosurePath, "utf8"));
  const result = verifyGovernanceDisclosure(disclosure, {
    expected_merkle_root: value("--expected-merkle-root"),
    expected_transcript_root: value("--expected-transcript-root")
  });
  process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
  process.exitCode = result.valid ? 0 : 2;
} catch (error) {
  process.stderr.write(`${error.message || error}\n`);
  process.exitCode = 1;
}
