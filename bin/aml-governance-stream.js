#!/usr/bin/env node

import fs from "node:fs";
import readline from "node:readline";
import { createGovernanceStreamSession, AML_GOVERNANCE_STREAM_OPEN, AML_GOVERNANCE_STREAM_ERROR } from "../protocol/governanceStream.js";

const file = process.argv[2] && process.argv[2] !== "-" ? process.argv[2] : null;
const input = file ? fs.createReadStream(file, "utf8") : process.stdin;
const rl = readline.createInterface({ input, crlfDelay: Infinity });

let session = null;
let lineNumber = 0;

function emit(value) {
  process.stdout.write(`${JSON.stringify(value)}\n`);
}

try {
  for await (const raw of rl) {
    lineNumber += 1;
    const line = raw.trim();
    if (!line) continue;
    const message = JSON.parse(line);
    if (!session) {
      if (message.protocol !== AML_GOVERNANCE_STREAM_OPEN) {
        throw new Error("first NDJSON message must be aml-governance-stream-open/1");
      }
      session = createGovernanceStreamSession(message);
      emit({
        protocol: AML_GOVERNANCE_STREAM_OPEN,
        accepted: true,
        transmission: session.transmission,
        profile: session.profile,
        mode: session.mode,
        failure_mode: session.failure_mode
      });
      continue;
    }
    emit(session.accept(message));
  }

  if (!session) throw new Error("governance stream contained no open message");
  if (!session.finalized) {
    throw new Error("governance stream ended before aml-governance-stream-finalize/1");
  }
} catch (error) {
  emit({
    protocol: AML_GOVERNANCE_STREAM_ERROR,
    line: lineNumber || null,
    error: error.message || String(error)
  });
  process.exitCode = 1;
}
