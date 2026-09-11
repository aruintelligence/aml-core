#!/usr/bin/env node

import fs from "node:fs";
import { createGovernanceDisclosure } from "../protocol/governanceDisclosure.js";

const transcriptPath = process.argv[2];
const indicesArg = process.argv[3];
if (!transcriptPath || !indicesArg) {
  console.error("Usage: aml-governance-disclose <transcript.json> <comma-separated-zero-based-indices>");
  process.exit(1);
}

try {
  const transcript = JSON.parse(fs.readFileSync(transcriptPath, "utf8"));
  const indices = indicesArg.split(",").filter(Boolean).map(value => Number(value));
  const disclosure = createGovernanceDisclosure(transcript, indices);
  process.stdout.write(`${JSON.stringify(disclosure, null, 2)}\n`);
} catch (error) {
  process.stderr.write(`${error.message || error}\n`);
  process.exitCode = 1;
}
