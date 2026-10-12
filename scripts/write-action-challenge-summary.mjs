#!/usr/bin/env node
import fs from "node:fs";
import { pathToFileURL } from "node:url";

export function actionChallengeSummary(report, artifactUrl = "") {
  if (report?.protocol !== "aml-action-boundary-challenge-report/1" ||
      report.case_scope !== "full" || !Array.isArray(report.cases) ||
      ![13, 19].includes(report.cases.length)) throw new TypeError("unsupported_challenge_report");
  const plain = value => typeof value === "string" && /^[a-z0-9:_-]+$/.test(value) ? value : "invalid";
  const count = report.cases.filter(row => row.passed).length;
  const total = report.cases.length;
  const status = report.full_challenge_passed === true && count === total ? "PASS" :
    count === 0 ? "FAIL" : "MIXED";
  const lines = [
    "## ĀML Action Boundary Challenge",
    "",
    `**${status} · ${count}/${total} cases** — adapter run; compatibility with project-defined fixtures only.`,
    ...(report.probe_seed ? ["", `13 published cases + ${plain(String(report.probe_case_count))} seeded probes. Reproduce with \`--probes --probe-seed ${plain(report.probe_seed)}\`.`] : []),
    "",
    "| Case | Result | Failure codes |",
    "| --- | --- | --- |",
    ...report.cases.map(row => `| \`${plain(row.id)}\` | ${row.passed ? "PASS" : "FAIL"} | ${row.passed ? "—" : row.failures.map(plain).map(code => `\`${code}\``).join(", ") || "invalid"} |`),
    "",
    `Manifest SHA-256: \`${plain(report.challenge_sha256)}\`  `,
    `Vectors SHA-256: \`${plain(report.vectors_sha256)}\``,
    "",
    "The artifact contains the exact JSON report and an offline visual HTML report, including failed cases. The adapter and its provenance require separate review."
  ];
  if (/^https:\/\/github\.com\/[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+\/actions\/runs\/\d+\/artifacts\/\d+$/.test(artifactUrl)) {
    lines.push("", `[Download both reports](${artifactUrl})`);
  }
  return lines.join("\n") + "\n";
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const report = JSON.parse(fs.readFileSync(process.argv[2], "utf8"));
  fs.appendFileSync(process.env.GITHUB_STEP_SUMMARY, actionChallengeSummary(report, process.env.AML_ARTIFACT_URL));
}
