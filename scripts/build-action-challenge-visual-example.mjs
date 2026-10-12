#!/usr/bin/env node
// Deterministic, clearly labeled project reference example for GitHub Pages.
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { renderActionChallengeReport } from "./render-action-challenge-report.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const output = path.join(root, "docs/action-challenge-run.html");
const run = spawnSync(process.execPath, [path.join(root, "scripts/run-action-boundary-challenge.mjs"), "--self-test"],
  { cwd: root, encoding: "utf8", timeout: 30000 });
assert.equal(run.status, 0, run.stderr);
const report = JSON.parse(run.stdout);
assert.equal(report.project_reference_self_test, true);
assert.equal(report.case_scope, "full");
assert.equal(report.cases.length, 13);
const html = renderActionChallengeReport(report);
if (process.argv.includes("--check")) {
  assert.equal(fs.readFileSync(output, "utf8"), html, "Visual challenge example is stale");
  console.log("Verified 13-case project reference visual example");
} else {
  fs.writeFileSync(output, html);
  console.log("Wrote 13-case project reference visual example");
}
