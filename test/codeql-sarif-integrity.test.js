// Authored recovery regressions; synthetic inputs do not authenticate scan origin.
import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { CODEQL_SCOPE, summarizeCodeql } from "../scripts/check-codeql-sarif.mjs";
const root = new URL("../", import.meta.url);
const checker = new URL("../scripts/check-codeql-sarif.mjs", import.meta.url).pathname;
const crashWorker = new URL("../scripts/test-fixtures/evidence-checker-crash.mjs", import.meta.url).pathname;
function report(language = "javascript-typescript") {
  return { version: "2.1.0", runs: [{
    tool: { driver: { name: "CodeQL", semanticVersion: "0.0.0-test", notifications: [
      { id: "js/parse-error" }, { id: "benign/cache-miss" }], rules: [] },
    extensions: [{ name: "synthetic-queries", rules: [{ id: language === "python" ? "py/example" : "js/example", defaultConfiguration: { level: "error" } }],
      notifications: [{ id: "js/diagnostics/extraction-errors" }, { id: "py/diagnostics/extraction-warnings" }] }] },
    invocations: [{ executionSuccessful: true }], results: [],
    properties: { incrementalMode: "none", codeqlConfigSummary: { queries: [{ uses: "security-extended" }] } },
    artifacts: CODEQL_SCOPE[language].map(name => ({ location: { uri: "pilots/action-boundary/" + name } }))
  }] };
}
const summarize = s => summarizeCodeql(s, "javascript-typescript");
const notification = (id = "js/parse-error", extra = {}) => ({ message: { text: "Synthetic parse failure" }, descriptor: { id }, ...extra });
const finding = extra => ({ ruleId: "js/example", message: { text: "Synthetic finding" }, ...extra });
const withFile = callback => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "aml-sarif-recovery-"));
  try { return callback(dir); } finally { fs.rmSync(dir, { recursive: true, force: true }); }
};
for (const level of [undefined, "none", "note", "warning", "error"]) {
  test(`known parser/extraction failure cannot become clean at level ${String(level)}`, () => {
    for (const id of ["js/parse-error", "js/diagnostics/extraction-errors"]) {
      const s = report(); s.runs[0].invocations[0].toolExecutionNotifications = [notification(id, level === undefined ? {} : { level })];
      const r = summarize(s); assert.equal(r.analysis_quality_valid, false); assert.equal(r.security_clean, false);
      assert.equal(r.extraction_or_configuration_errors[0].id, id); assert.deepEqual(r.notifications[0].message, { text: "Synthetic parse failure" });
    }
  });
}
test("Python SyntaxError extraction-warnings are incomplete evidence, not benign telemetry", () => {
  const s = report("python"); s.runs[0].invocations[0].toolConfigurationNotifications = [notification("py/diagnostics/extraction-warnings", { level: "warning" })];
  const r = summarizeCodeql(s, "python"); assert.equal(r.analysis_quality_valid, false); assert.equal(r.security_clean, false);
});
test("known parser-warning partial report preserves every finding and baseline/suppression", () => {
  const s = report(); s.runs[0].invocations[0].toolExecutionNotifications = [notification()];
  s.runs[0].results = [finding({ baselineState: "unchanged", suppressions: [{ kind: "external", status: "accepted" }] })];
  const r = summarize(s); assert.equal(r.findings_count, 1); assert.equal(r.findings_by_level.error, 1);
  assert.equal(r.findings[0].suppressions_present, true); assert.equal(r.analysis_quality_valid, false);
});
test("benign warnings and absent optional arrays remain allowed and visible", () => {
  const s = report(); const inv = s.runs[0].invocations[0];
  assert.equal(summarize(s).analysis_quality_valid, true);
  inv.toolExecutionNotifications = [notification("benign/cache-miss", { level: "warning", message: { text: "Cold cache, full extraction still ran" } })];
  const r = summarize(s); assert.equal(r.analysis_quality_valid, true); assert.equal(r.notifications.length, 1);
});
for (const key of ["toolExecutionNotifications", "toolConfigurationNotifications"]) {
  for (const value of [null, {}, "not-an-array", false]) test(`reject ${key} type ${JSON.stringify(value)}`, () => {
    const s = report(); s.runs[0].invocations[0][key] = value; assert.throws(() => summarize(s), /invalid_codeql_notifications/);
  });
}
for (const value of [null, {}, "bad", { message: null }, { message: {} }, { message: { text: 1 } }, { message: { markdown: "only" } }]) {
  test(`malformed notification cannot silently disappear: ${JSON.stringify(value)}`, () => {
    const s = report(); s.runs[0].invocations[0].toolExecutionNotifications = [value]; assert.throws(() => summarize(s));
  });
}
const mutations = {
  "missing runs": s => delete s.runs,
  "null runs": s => { s.runs = null; },
  "empty runs": s => { s.runs = []; },
  "wrong runs": s => { s.runs = {}; },
  "null run": s => { s.runs = [null]; },
  "missing tool": s => delete s.runs[0].tool,
  "null tool": s => { s.runs[0].tool = null; },
  "missing driver": s => delete s.runs[0].tool.driver,
  "null driver": s => { s.runs[0].tool.driver = null; },
  "null semantic version with fallback": s => { s.runs[0].tool.driver.semanticVersion = null; s.runs[0].tool.driver.version = "1.0.0"; },
  "missing results": s => delete s.runs[0].results,
  "null results": s => { s.runs[0].results = null; },
  "wrong results": s => { s.runs[0].results = {}; },
  "null result": s => { s.runs[0].results = [null]; },
  "missing result message": s => { s.runs[0].results = [{ ruleId: "js/example" }]; },
  "null result rule reference": s => { s.runs[0].results = [finding({ rule: null })]; },
  "missing invocations": s => delete s.runs[0].invocations,
  "null invocations": s => { s.runs[0].invocations = null; },
  "empty invocations": s => { s.runs[0].invocations = []; },
  "null invocation": s => { s.runs[0].invocations = [null]; },
  "missing successful flag": s => { s.runs[0].invocations = [{}]; },
  "false successful flag": s => { s.runs[0].invocations = [{ executionSuccessful: false }]; },
  "string successful flag": s => { s.runs[0].invocations = [{ executionSuccessful: "true" }]; },
  "nonzero exit": s => { s.runs[0].invocations[0].exitCode = 2; },
  "signal termination": s => { s.runs[0].invocations[0].exitSignalName = "SIGKILL"; },
  "start failure": s => { s.runs[0].invocations[0].processStartFailureMessage = "failed"; },
  "null extensions": s => { s.runs[0].tool.extensions = null; },
  "null descriptors": s => { s.runs[0].tool.driver.notifications = null; },
  "duplicate descriptor": s => { s.runs[0].tool.driver.notifications.push({ id: "js/parse-error" }); },
  "null diagnostic level": s => { s.runs[0].invocations[0].toolExecutionNotifications = [notification(undefined, { level: null })]; },
  "unknown descriptor": s => { s.runs[0].invocations[0].toolExecutionNotifications = [notification("unknown")]; },
  "null locations": s => { s.runs[0].invocations[0].toolExecutionNotifications = [notification(undefined, { locations: null })]; },
  "null artifacts": s => { s.runs[0].artifacts = null; },
  "null query entry": s => { s.runs[0].properties.codeqlConfigSummary.queries.push(null); },
  "externalized results": s => { s.runs[0].externalPropertyFileReferences = { results: [{ itemCount: 28, location: { uri: "missing.json" } }] }; },
  "unhandled runtime overrides": s => { s.runs[0].invocations[0].notificationConfigurationOverrides = [{ configuration: { level: "none" }, descriptor: { id: "js/parse-error" } }]; }
};
for (const [name, mutate] of Object.entries(mutations)) test(`fail closed metadata: ${name}`, () => {
  const s = report(); mutate(s); assert.throws(() => summarize(s));
});
test("index-only descriptor resolves parser failure; conflicting id/index rejects", () => {
  const s = report(); const n = notification(); n.descriptor = { index: 0 }; s.runs[0].invocations[0].toolExecutionNotifications = [n];
  assert.equal(summarize(s).analysis_quality_valid, false);
  n.descriptor.id = "benign/cache-miss"; assert.throws(() => summarize(s), /unresolved_codeql_descriptor_reference/);
});
test("component-qualified descriptor cannot borrow severity from another pack", () => {
  const s = report(); s.runs[0].tool.extensions[0].notifications.push({ id: "js/parse-error", defaultConfiguration: { level: "none" } });
  const n = notification(); s.runs[0].invocations[0].toolExecutionNotifications = [n];
  assert.throws(() => summarize(s), /unresolved_codeql_descriptor_reference/);
  n.descriptor.toolComponent = { index: -1 }; assert.equal(summarize(s).analysis_quality_valid, false);
  n.descriptor.toolComponent = { index: 0 }; assert.equal(summarize(s).analysis_quality_valid, false);
});
test("diff-informed/unknown scope cannot be called complete; findings are retained", () => {
  for (const mode of ["diff-informed", "overlay", null, undefined]) {
    const s = report(); s.runs[0].properties.incrementalMode = mode; s.runs[0].results = [finding()];
    const r = summarize(s); assert.equal(r.analysis_quality_valid, false); assert.equal(r.security_clean, false); assert.equal(r.findings_count, 1);
  }
});
test("forged CodeQL metadata can pass format checks: expected provenance LIMIT, not scanner proof", () => {
  const r = summarize(report()); assert.equal(r.analysis_quality_valid, true);
  assert.match(r.claim_boundary, /not scanner authentication/); // An attacker can construct this JSON. No signature trust claimed.
});
test("workflow explicitly disables diff-only/overlay modes without disabling queries", () => {
  const workflow = fs.readFileSync(new URL(".github/workflows/codeql.yml", root), "utf8");
  assert.match(workflow, /CODEQL_ACTION_DIFF_INFORMED_QUERIES: "false"/);
  assert.match(workflow, /CODEQL_ACTION_OVERLAY_ANALYSIS: "false"/);
  assert.match(workflow, /queries: security-extended/); assert.doesNotMatch(workflow, /skip-queries:/);
});
for (const fault of ["before", "after"]) test(`SARIF checker process crash ${fault} validation is not a success result`, () => withFile(dir => {
  const s = report(), raw = JSON.stringify(s), file = path.join(dir, "result.sarif"); fs.writeFileSync(file, raw);
  const child = spawnSync(process.execPath, [crashWorker, "sarif", fault], { input: raw, encoding: "utf8", timeout: 10000 });
  assert.ifError(child.error); assert.equal(child.signal, "SIGKILL"); assert.equal(child.status, null); assert.equal(child.stdout, "");
  assert.equal(fs.readFileSync(file, "utf8"), raw);
  const restart = spawnSync(process.execPath, [checker, dir, "javascript-typescript"], { encoding: "utf8", timeout: 10000 });
  assert.ifError(restart.error); assert.equal(restart.status, 0, restart.stderr);
  assert.equal(JSON.parse(restart.stdout).analysis_quality_valid, true);
  assert.equal(fs.readFileSync(file, "utf8"), raw);
}));
