#!/usr/bin/env node
/**
 * Independent verifier for ĀML Decision Core 1.
 *
 * This file intentionally imports no aml-core modules. It implements the
 * published conformance rule directly from CONFORMANCE.md and the vectors.
 */

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(here, "..");
const protocol = "aml-conformance/decision-core-1";

function load(name) {
  const payload = JSON.parse(fs.readFileSync(path.resolve(root, name), "utf8"));
  if (payload.protocol !== protocol) {
    throw new Error(`unexpected conformance protocol in ${name}`);
  }
  return payload;
}

function decision(attentionCost, restorationValue) {
  if (typeof attentionCost !== "number" || typeof restorationValue !== "number") {
    throw new TypeError("scores must be JSON numbers");
  }
  if (!Number.isFinite(attentionCost) || !Number.isFinite(restorationValue)) {
    throw new TypeError("scores must be finite JSON numbers");
  }
  return restorationValue >= attentionCost ? "ALLOW" : "SUPPRESS";
}

let payload;
let invalidPayload;
try {
  payload = load("decision-core-1.json");
  invalidPayload = load("decision-core-1-invalid.json");
} catch (error) {
  console.error(`FAIL: ${error.message}`);
  process.exit(2);
}

const failures = [];
for (const vector of payload.vectors) {
  try {
    const actual = decision(vector.attention_cost, vector.restoration_value);
    if (actual !== vector.expected_decision) {
      failures.push({ id: vector.id, expected: vector.expected_decision, actual });
    }
  } catch (error) {
    failures.push({ id: vector.id, expected: vector.expected_decision, actual: `ERROR:${error.name}` });
  }
}

let rejected = 0;
for (const vector of invalidPayload.vectors) {
  try {
    decision(vector.attention_cost, vector.restoration_value);
    failures.push({ id: vector.id, expected: "REJECT", actual: "ACCEPT" });
  } catch (error) {
    if (error instanceof TypeError) {
      rejected += 1;
    } else {
      failures.push({ id: vector.id, expected: "REJECT", actual: `ERROR:${error.name}` });
    }
  }
}

if (failures.length) {
  for (const failure of failures) {
    console.error(`FAIL ${failure.id}: expected ${failure.expected}, got ${failure.actual}`);
  }
  process.exit(1);
}

const validCount = payload.vectors.length;
const invalidCount = invalidPayload.vectors.length;
console.log(`PASS ${protocol} (${validCount}/${validCount} decisions; ${rejected}/${invalidCount} invalid rejected)`);
