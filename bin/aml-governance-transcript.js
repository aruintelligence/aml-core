#!/usr/bin/env node

import fs from "node:fs";
import { createGovernanceStreamTranscript } from "../protocol/governanceTranscript.js";

const file = process.argv[2] && process.argv[2] !== "-" ? process.argv[2] : null;

try {
  const raw = file ? fs.readFileSync(file, "utf8") : fs.readFileSync(0, "utf8");
  const messages = raw.split(/\r?\n/).map(line => line.trim()).filter(Boolean).map(line => JSON.parse(line));
  const transcript = createGovernanceStreamTranscript(messages);
  process.stdout.write(`${JSON.stringify(transcript, null, 2)}\n`);
} catch (error) {
  process.stderr.write(`${error.message || error}\n`);
  process.exitCode = 1;
}
