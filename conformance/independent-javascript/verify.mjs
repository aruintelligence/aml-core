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
const vectorPath = path.resolve(here, "..", "decision-core-1.json");
const payload = JSON.parse(fs.readFileSync(vectorPath, "utf8"));

function decision(attentionCost, restorationValue) {
  if (typeof attentionCost !== "number" || typeof restorationValue !== "number") {
    throw new TypeError("scores must be JSON numbers");
  }
  if (!Number.isFinite(attentionCost) || !Number.isFinite(restorationValue)) {
    throw new TypeError("scores must be finite JSON numbers");
  }
  return restorationValue >= attentionCost ? "ALLOW" : "SUPPRESS";
}

if (payload.protocol !== "aml-conformance/decision-core-1") {
  console.error("FAIL: unexpected conformance protocol");
  process.exit(2);
}

const failures = [];
for (const vector of payload.vectors) {
  const actual = decision(vector.attention_cost, vector.restoration_value);
  if (actual !== vector.expected_decision) {
    failures.push({ id: vector.id, expected: vector.expected_decision, actual });
  }
}

if (failures.length) {
  for (const failure of failures) {
    console.error(`FAIL ${failure.id}: expected ${failure.expected}, got ${failure.actual}`);
  }
  process.exit(1);
}

console.log(`PASS aml-conformance/decision-core-1 (${payload.vectors.length}/${payload.vectors.length} vectors)`);
