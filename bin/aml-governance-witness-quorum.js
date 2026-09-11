#!/usr/bin/env node

import fs from "node:fs";
import { evaluateGovernanceWitnessQuorum } from "../protocol/governanceWitnessQuorum.js";

const inputPath = process.argv[2];
if (!inputPath) {
  console.error("Usage: aml-governance-witness-quorum <quorum-input.json>");
  process.exit(1);
}

try {
  const input = JSON.parse(fs.readFileSync(inputPath, "utf8"));
  if (!Array.isArray(input.signed_transcripts)) throw new Error("signed_transcripts array is required");
  const result = evaluateGovernanceWitnessQuorum(input.signed_transcripts, input.policy || {});
  process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
  if (!result.quorum_met) process.exitCode = 2;
} catch (error) {
  process.stderr.write(`${error.message || error}\n`);
  process.exitCode = 1;
}
