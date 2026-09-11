#!/usr/bin/env node

import fs from "node:fs";
import { evaluateAgentUI } from "../adapters/agent-ui.js";

function argValue(name, fallback = null) {
  const index = process.argv.indexOf(name);
  return index >= 0 ? process.argv[index + 1] ?? fallback : fallback;
}

const file = process.argv.slice(2).find(arg => !arg.startsWith("--") && !["enforce", "shadow"].includes(arg));
const profile = argValue("--profile", process.env.AML_PROFILE || "calm_default");
const mode = argValue("--mode", process.env.AML_MODE || "enforce");
const failureMode = argValue("--failure-mode", process.env.AML_FAILURE_MODE || "closed");
const timestamp = argValue("--timestamp", process.env.AML_TIMESTAMP || undefined);

try {
  const raw = file && file !== "-" ? fs.readFileSync(file, "utf8") : fs.readFileSync(0, "utf8");
  const envelope = JSON.parse(raw);
  const result = evaluateAgentUI(envelope, {
    profile,
    mode,
    failure_mode: failureMode,
    timestamp
  });
  process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
  if (result.errors > 0) process.exitCode = 2;
} catch (error) {
  process.stderr.write(`${error.message || error}\n`);
  process.exitCode = 1;
}
