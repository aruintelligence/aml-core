import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { actionChallengeSummary } from "../scripts/write-action-challenge-summary.mjs";

const published = readFileSync(new URL("../docs/action-challenge-run.html", import.meta.url), "utf8");
const referenceReport = JSON.parse(published.match(/<script type="application\/json" id="report-data">([^<]*)<\/script>/)?.[1] ?? "null");

test("GitHub summary reports all observed cases and links the visual artifact", () => {
  const summary = actionChallengeSummary(referenceReport, "https://github.com/example/adapter/actions/runs/123/artifacts/456");
  assert.match(summary, /PASS · 13\/13 cases/);
  assert.match(summary, /\| `policy-revoked-while-awaiting` \| PASS \|/);
  assert.match(summary, /\[Download both reports\]\(https:\/\/github.com\/example\/adapter\/actions\/runs\/123\/artifacts\/456\)/);
  assert.equal((summary.match(/\| PASS \|/g) ?? []).length, 13);
});

test("failed result remains visible while untrusted text cannot inject summary markup", () => {
  const report = structuredClone(referenceReport);
  report.passed = false;
  report.full_challenge_passed = false;
  report.cases.forEach(row => { row.passed = false; row.failures = ["result_protocol"]; });
  report.cases[0].failures.push("[click me](https://evil.example) | <img src=x>");
  const summary = actionChallengeSummary(report, "javascript:alert(1)");
  assert.match(summary, /FAIL · 0\/13 cases/);
  assert.match(summary, /\| `approved-send` \| FAIL \|/);
  assert.ok(!summary.includes("evil.example"));
  assert.ok(!summary.includes("javascript:"));
  assert.ok(!summary.includes("<img"));
  assert.throws(() => actionChallengeSummary({ ...report, case_scope: "single" }), /unsupported_challenge_report/);
});
