import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("..", import.meta.url));
const reportHash = (report) => {
  const { report_sha256, ...payload } = report;
  return crypto.createHash("sha256").update(JSON.stringify(payload)).digest("hex");
};

function run(args, options = {}) {
  return spawnSync(process.execPath, args, { cwd: root, encoding: "utf8", ...options });
}

test("enterprise pilot records actual checkout revision, not a caller environment claim", () => {
  const git = spawnSync("git", ["rev-parse", "--verify", "HEAD"], { cwd: root, encoding: "utf8" });
  assert.equal(git.status, 0);
  const result = run(["pilots/enterprise-30min/run.mjs"], {
    env: { ...process.env, GITHUB_SHA: "0".repeat(40) }
  });
  assert.equal(result.status, 0, result.stderr);
  const report = JSON.parse(result.stdout);
  assert.equal(report.source_revision, git.stdout.trim());
  assert.equal(typeof report.tracked_worktree_modified, "boolean");
});

test("enterprise pilot verifier rejects a forged revision even with a recomputed report digest", () => {
  const generated = run(["pilots/enterprise-30min/run.mjs"]);
  assert.equal(generated.status, 0, generated.stderr);
  const report = JSON.parse(generated.stdout);
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "aml-enterprise-source-"));
  try {
    const reportPath = path.join(directory, "report.json");
    fs.writeFileSync(reportPath, JSON.stringify(report));
    const valid = run(["pilots/enterprise-30min/verify-report.mjs", reportPath]);
    assert.equal(valid.status, 0, valid.stderr);

    report.source_revision = "0".repeat(40);
    report.report_sha256 = reportHash(report);
    fs.writeFileSync(reportPath, JSON.stringify(report));
    const forged = run(["pilots/enterprise-30min/verify-report.mjs", reportPath]);
    assert.notEqual(forged.status, 0);
    assert.match(forged.stderr, /source revision mismatch/);

    report.source_revision = JSON.parse(generated.stdout).source_revision;
    report.tracked_worktree_modified = !report.tracked_worktree_modified;
    report.report_sha256 = reportHash(report);
    fs.writeFileSync(reportPath, JSON.stringify(report));
    const misreportedChanges = run(["pilots/enterprise-30min/verify-report.mjs", reportPath]);
    assert.notEqual(misreportedChanges.status, 0);
    assert.match(misreportedChanges.stderr, /tracked worktree status mismatch/);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});
