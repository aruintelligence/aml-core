#!/usr/bin/env node

import { finishConsistencyCommand, diagnosticOnlyRequested } from "../runtime/commandAuthorization.js";
import fs from "node:fs";
import { evaluateGovernanceWitnessQuorum } from "../protocol/governanceWitnessQuorum.js";

const diagnosticOnly = diagnosticOnlyRequested(process.argv.slice(2));
const inputPath = process.argv.slice(2).filter(arg => arg !== "--diagnostic-only")[0];
if (!inputPath) {
  console.error("Usage: aml-governance-witness-quorum <quorum-input.json>");
  process.exit(1);
}

try {
  const input = JSON.parse(fs.readFileSync(inputPath, "utf8"));
  if (!Array.isArray(input.signed_transcripts)) throw new Error("signed_transcripts array is required");
  const result = evaluateGovernanceWitnessQuorum(input.signed_transcripts, input.policy || {});
  await finishConsistencyCommand(result, result.quorum_met, { diagnosticOnly, invalidCode: 2 });
} catch (error) {
  process.stderr.write(`${error.message || error}\n`);
  process.exitCode = 1;
}
