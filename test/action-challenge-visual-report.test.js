import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { renderActionChallengeReport } from "../scripts/render-action-challenge-report.mjs";

const root = fileURLToPath(new URL("..", import.meta.url));
const runner = path.join(root, "scripts/run-action-boundary-challenge.mjs");
const invoke = (args) => spawnSync(process.execPath, [runner, ...args],
  { cwd: root, encoding: "utf8", timeout: 30000 });
const embedded = html => JSON.parse(html.match(/<script type="application\/json" id="report-data">([^<]*)<\/script>/)?.[1] ?? "null");

test("self-test can export an offline, full-scope visual result without changing JSON stdout", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "aml-visual-report-"));
  try {
    const file = path.join(directory, "full.html");
    const run = invoke(["--self-test", "--html-out", file]);
    assert.equal(run.status, 0, run.stderr);
    const report = JSON.parse(run.stdout);
    assert.equal(report.cases.length, 13);
    assert.equal(report.full_challenge_passed, true);
    assert.deepEqual(embedded(fs.readFileSync(file, "utf8")), report);
    assert.match(fs.readFileSync(file, "utf8"), /PROJECT REFERENCE SELF-TEST/);
    const second = invoke(["--self-test", "--html-out", file]);
    assert.equal(second.status, 2, "existing visual files are not overwritten");
    assert.match(second.stderr, /Cannot create visual report/);
  } finally { fs.rmSync(directory, { recursive: true, force: true }); }
});

test("focused and failed external-adapter runs retain their honest scope and diagnostics", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "aml-visual-scope-"));
  try {
    const focused = path.join(directory, "focused.html");
    const success = invoke(["--self-test", "--case", "changed-destination", "--html-out", focused]);
    assert.equal(success.status, 0, success.stderr);
    assert.equal(embedded(fs.readFileSync(focused, "utf8")).full_challenge_passed, false);
    assert.equal(embedded(fs.readFileSync(focused, "utf8")).case_scope, "single");

    const failed = path.join(directory, "failed.html");
    const mismatch = invoke(["--case", "changed-destination", "--html-out", failed,
      "--", process.execPath, "-e", "process.stdout.write('{}')"]);
    assert.equal(mismatch.status, 1);
    const report = embedded(fs.readFileSync(failed, "utf8"));
    assert.equal(report.project_reference_self_test, false);
    assert.equal(report.passed, false);
    assert.ok(report.cases[0].failures.length > 0);
    assert.ok(report.cases[0].diagnostics.length > 0);
    assert.deepEqual(JSON.parse(mismatch.stdout), report);
  } finally { fs.rmSync(directory, { recursive: true, force: true }); }
});

test("malicious adapter text remains JSON data, never markup or executable script", () => {
  const payload = "</script><script>globalThis.injected=true</script><img src=x onerror=alert(1)>";
  const report = { protocol: "aml-action-boundary-challenge-report/1",
    project_reference_self_test: false, case_scope: "single", passed: false,
    cases: [{ id: "injection", passed: false, failures: [payload],
      diagnostics: [{ field: payload, expected: payload, actual: payload }] }] };
  const html = renderActionChallengeReport(report);
  assert.deepEqual(embedded(html), report);
  assert.equal(html.includes(payload), false);
  assert.equal((html.match(/<script>/g) ?? []).length, 1, "only the authored script is executable");
  assert.match(html, /\\u003c\/script\\u003e/);
  assert.throws(() => renderActionChallengeReport({ cases: [] }), /unsupported_action_challenge_report/);
});
