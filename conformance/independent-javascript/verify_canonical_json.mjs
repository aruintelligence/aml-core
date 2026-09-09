#!/usr/bin/env node

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const vectorsPath = path.resolve(here, "..", "..", "protocol", "browser-canonicalization-vectors.json");
const data = JSON.parse(fs.readFileSync(vectorsPath, "utf8"));

function canonicalize(value) {
  if (Array.isArray(value)) {
    return `[${value.map(canonicalize).join(",")}]`;
  }
  if (value !== null && typeof value === "object") {
    const entries = Object.keys(value)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${canonicalize(value[key])}`);
    return `{${entries.join(",")}}`;
  }
  return JSON.stringify(value);
}

if (data.canonicalization !== "sorted-json-v1") {
  console.error("FAIL: unexpected canonicalization identifier");
  process.exit(2);
}

const failures = [];
for (const vector of data.vectors) {
  const rendered = canonicalize(vector.input);
  const digest = crypto.createHash("sha256").update(rendered, "utf8").digest("hex");
  if (rendered !== vector.canonical) {
    failures.push(`${vector.name}: canonical mismatch`);
  }
  if (digest !== vector.sha256) {
    failures.push(`${vector.name}: sha256 mismatch`);
  }
}

if (failures.length) {
  for (const failure of failures) console.error(`FAIL ${failure}`);
  process.exit(1);
}

console.log(`PASS aml-conformance/canonical-json-1 (${data.vectors.length}/${data.vectors.length} vectors)`);
