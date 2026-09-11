#!/usr/bin/env node

import fs from "node:fs";
import { verifyGovernanceStreamTranscript } from "../protocol/governanceTranscript.js";

const file = process.argv[2] && process.argv[2] !== "-" ? process.argv[2] : null;

try {
  const raw = file ? fs.readFileSync(file, "utf8") : fs.readFileSync(0, "utf8");
  const transcript = JSON.parse(raw);
  const verification = verifyGovernanceStreamTranscript(transcript);
  process.stdout.write(`${JSON.stringify(verification, null, 2)}\n`);
  if (!verification.valid) process.exitCode = 2;
} catch (error) {
  process.stderr.write(`${error.message || error}\n`);
  process.exitCode = 1;
}
