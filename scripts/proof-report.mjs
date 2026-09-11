#!/usr/bin/env node

import fs from "node:fs";
import os from "node:os";
import process from "node:process";
import { spawnSync } from "node:child_process";

const runJson = (command, args) => {
  const result = spawnSync(command, args, {
    cwd: process.cwd(),
    encoding: "utf8"
  });

  if (result.status !== 0) {
    if (result.stdout) process.stdout.write(result.stdout);
    if (result.stderr) process.stderr.write(result.stderr);
    process.exit(result.status ?? 1);
  }

  try {
    return JSON.parse(result.stdout);
  } catch (error) {
    console.error(`Expected JSON from ${command} ${args.join(" ")}`);
    if (result.stdout) console.error(result.stdout);
    console.error(error.message);
    process.exit(1);
  }
};

const replay = runJson(process.execPath, ["demos/undeniable-proof/replay-proof.mjs"]);
const fixtures = runJson(process.execPath, ["scripts/check-flood-fixtures.js"]);

const report = {
  schema: "aru-aml-core-proof-report/1",
  result: replay.proof === "PASS" && fixtures.proof === "PASS" ? "PASS" : "FAIL",
  generated_at: new Date().toISOString(),
  environment: {
    node: process.version,
    platform: process.platform,
    arch: process.arch,
    os_release: os.release()
  },
  checks: {
    deterministic_replay: replay,
    balanced_render_fixtures: fixtures
  },
  evidence_boundary: {
    project_authored: true,
    independent_external_verification: false,
    note: "This report records execution of project-authored proof checks. It becomes independent evidence only when an external tester runs it and publishes their own reproducible result."
  },
  canonical_verification_issue: "https://github.com/aruintelligence/aml-core/issues/88"
};

const outputPath = process.argv[2] || "aml-proof-report.json";
fs.writeFileSync(outputPath, `${JSON.stringify(report, null, 2)}\n`, "utf8");

console.log(JSON.stringify({
  result: report.result,
  report: outputPath,
  replay_receipt_sha256: replay.receipt_sha256,
  replay_decision_sha256: replay.decision_sha256,
  replay_output_sha256: replay.output_sha256,
  fixtures_verified: fixtures.fixtures_verified
}, null, 2));

if (report.result !== "PASS") process.exit(1);
