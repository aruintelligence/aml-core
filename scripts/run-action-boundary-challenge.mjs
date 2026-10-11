#!/usr/bin/env node
// Black-box challenge for a caller-owned action boundary adapter.
// This program does not import the reference boundary or run a real tool.
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { prepareCase, checkCase } from "../conformance/action-boundary-challenge-core.js";

const split = process.argv.indexOf("--");
const selfTest = process.argv.includes("--self-test");
if (!selfTest && (split < 0 || split === process.argv.length - 1)) {
  console.error("Usage: node scripts/run-action-boundary-challenge.mjs -- <executable> [args...]");
  process.exit(2);
}
const command = selfTest ? null : process.argv[split + 1];
const args = selfTest ? [] : process.argv.slice(split + 2);
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const manifestBytes = fs.readFileSync(path.join(root, "conformance/action-boundary-challenge.json"));
const manifest = JSON.parse(manifestBytes);
const vectorBytes = fs.readFileSync(path.join(root, manifest.vectors_file));
const vectors = JSON.parse(vectorBytes);
const digest = value => crypto.createHash("sha256").update(value).digest("hex");
if (manifest.protocol !== "aml-action-boundary-challenge/1" ||
    vectors.protocol !== "aml-action-vectors/1" || !Array.isArray(manifest.cases) ||
    manifest.cases.length === 0) throw new Error("Unsupported or empty action challenge");
const temp = fs.mkdtempSync(path.join(os.tmpdir(), "aml-action-challenge-"));
const reference = selfTest ? await import("../pilots/action-boundary/challenge-reference-adapter.mjs") : null;

const ids = new Set();
const results = [];
try {
  for (const row of manifest.cases) {
    if (!/^[a-z0-9-]+$/.test(row.id) || ids.has(row.id)) throw new Error("Invalid or duplicate case id");
    ids.add(row.id);
    const input = prepareCase(row, vectors);
    const file = path.join(temp, `${row.id}.json`);
    fs.writeFileSync(file, JSON.stringify(input));
    const invocation = selfTest ?
      { status: 0, stdout: JSON.stringify(await reference.runReferenceCase(input)) } :
      spawnSync(command, [...args, file], {
        encoding: "utf8", cwd: process.cwd(), timeout: 5000, maxBuffer: 256 * 1024
      });
    let output = null;
    try { output = JSON.parse((invocation.stdout || "").trim()); } catch {}
    const failures = checkCase(row, output, invocation, vectors);
    if (!output) failures.push("single_json_stdout");
    results.push({ id: row.id, passed: failures.length === 0, failures });
  }
} finally {
  fs.rmSync(temp, { recursive: true, force: true });
}
const passed = results.every(row => row.passed);
console.log(JSON.stringify({
  protocol: "aml-action-boundary-challenge-report/1",
  project_reference_self_test: selfTest,
  challenge_sha256: digest(manifestBytes),
  vectors_sha256: digest(vectorBytes),
  passed,
  cases: results,
  claim_boundary: manifest.claim_boundary
}, null, 2));
process.exitCode = passed ? 0 : 1;
