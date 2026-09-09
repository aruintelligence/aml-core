#!/usr/bin/env node

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";

const here = path.dirname(fileURLToPath(import.meta.url));
const protocol = "aml-conformance/decision-core-1";
const valid = JSON.parse(fs.readFileSync(path.join(here, "decision-core-1.json"), "utf8"));
const invalid = JSON.parse(fs.readFileSync(path.join(here, "decision-core-1-invalid.json"), "utf8"));

if (valid.protocol !== protocol || invalid.protocol !== protocol) {
  console.error("FAIL: vector protocol mismatch");
  process.exit(2);
}

let command = process.argv.slice(2);
if (command[0] === "--") command = command.slice(1);
if (!command.length) {
  console.error("usage: node conformance/run-external.mjs -- <command> [args...]");
  process.exit(2);
}

function invoke(vector) {
  return spawnSync(command[0], command.slice(1), {
    input: JSON.stringify(vector),
    encoding: "utf8",
    timeout: 5000,
    env: { ...process.env, AML_CONFORMANCE_PROTOCOL: protocol }
  });
}

const failures = [];

for (const vector of valid.vectors) {
  const input = {
    attention_cost: vector.attention_cost,
    restoration_value: vector.restoration_value
  };
  const result = invoke(input);
  if (result.error) {
    failures.push(`${vector.id}: process error ${result.error.message}`);
    continue;
  }
  if (result.status !== 0) {
    failures.push(`${vector.id}: expected exit 0, got ${result.status}; stderr=${result.stderr.trim()}`);
    continue;
  }
  let output;
  try {
    output = JSON.parse(result.stdout.trim());
  } catch {
    failures.push(`${vector.id}: stdout was not valid JSON`);
    continue;
  }
  if (output.decision !== vector.expected_decision) {
    failures.push(`${vector.id}: expected ${vector.expected_decision}, got ${JSON.stringify(output.decision)}`);
  }
}

let rejected = 0;
for (const vector of invalid.vectors) {
  const input = { ...vector };
  delete input.id;
  const result = invoke(input);
  if (result.error) {
    failures.push(`${vector.id}: process error ${result.error.message}`);
    continue;
  }
  if (result.status !== 0) {
    rejected += 1;
    continue;
  }
  let output;
  try {
    output = JSON.parse(result.stdout.trim());
  } catch {
    failures.push(`${vector.id}: invalid input exited 0 with non-JSON stdout`);
    continue;
  }
  if (typeof output.error === "string" && output.error.length > 0 && output.decision === undefined) {
    rejected += 1;
  } else {
    failures.push(`${vector.id}: invalid input was not rejected`);
  }
}

if (failures.length) {
  for (const failure of failures) console.error(`FAIL ${failure}`);
  process.exit(1);
}

console.log(`PASS ${protocol} external executable (${valid.vectors.length}/${valid.vectors.length} decisions; ${rejected}/${invalid.vectors.length} invalid rejected)`);
