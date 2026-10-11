#!/usr/bin/env node
// Compare actual JS and Python adapter outputs for the published 13 cases.
// Project-maintained comparison only: this is not an external witness.
import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { isDeepStrictEqual } from "node:util";
import { prepareCase, checkCase } from "../conformance/action-boundary-challenge-core.js";
import { runReferenceCase } from "../pilots/action-boundary/challenge-reference-adapter.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const manifestBytes = fs.readFileSync(path.join(root, "conformance/action-boundary-challenge.json"));
const vectorBytes = fs.readFileSync(path.join(root, "pilots/action-boundary/vectors.json"));
const manifest = JSON.parse(manifestBytes);
const vectors = JSON.parse(vectorBytes);
const digest = bytes => crypto.createHash("sha256").update(bytes).digest("hex");
const temp = fs.mkdtempSync(path.join(os.tmpdir(), "aml-cross-runtime-"));
const cases = [];
try {
  for (const row of manifest.cases) {
    const input = prepareCase(row, vectors);
    const file = path.join(temp, `${row.id}.json`);
    fs.writeFileSync(file, JSON.stringify(input));
    const js = await runReferenceCase(input);
    const invocation = spawnSync("python3", [path.join(root, "pilots/action-boundary/challenge-python-adapter.py"), file],
      { encoding: "utf8", timeout: 5000, maxBuffer: 256 * 1024 });
    if (invocation.error || invocation.status !== 0) {
      throw new Error(`${row.id}: Python adapter failed: ${invocation.error?.message || invocation.stderr}`);
    }
    const python = JSON.parse(invocation.stdout.trim());
    const js_failures = checkCase(row, js, { status: 0 }, vectors);
    const python_failures = checkCase(row, python, invocation, vectors);
    cases.push({ id: row.id, expected: row.expected, js, python,
      same_output: isDeepStrictEqual(js, python),
      js_failures, python_failures });
  }
} finally {
  fs.rmSync(temp, { recursive: true, force: true });
}
const report = { protocol: "aml-action-cross-runtime-report/1",
  provenance: "project-maintained JavaScript and Python implementations",
  challenge_sha256: digest(manifestBytes), vectors_sha256: digest(vectorBytes),
  cases, agreements: cases.filter(row => row.same_output).length,
  contract_passes: cases.filter(row => row.js_failures.length === 0 && row.python_failures.length === 0).length,
  limits: "13 published fixtures only. No outside implementation, authenticated approver, live tool, general JSON canonicalization, or independent validation." };
const outputFile = path.join(root, "docs/action-cross-runtime-report.json");
if (process.argv.includes("--check")) {
  assert.deepEqual(JSON.parse(fs.readFileSync(outputFile, "utf8")), report);
  assert.equal(report.agreements, manifest.cases.length);
  assert.equal(report.contract_passes, manifest.cases.length);
  console.log(`Verified ${report.agreements}/${manifest.cases.length} exact cross-runtime outputs and published report`);
} else {
  console.log(JSON.stringify(report, null, 2));
}
