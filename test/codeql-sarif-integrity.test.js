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
    tool: { driver: { name: "CodeQL", semanticVersion: "2.27.4", notifications: [
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
test("diff-informed/overlay/unknown scope cannot be called complete; findings are retained", () => {
  // Present-but-undefined/null/other values are not the pinned Action's full-analysis shape.
  for (const mode of ["diff-informed", "overlay", "diff-informed,overlay", "overlay,diff-informed", "", "NONE", "full", null, undefined, 0, false, ["none"], { mode: "none" }]) {
    const s = report(); s.runs[0].properties.incrementalMode = mode; s.runs[0].results = [finding()];
    const r = summarize(s); assert.equal(r.analysis_quality_valid, false); assert.equal(r.security_clean, false); assert.equal(r.findings_count, 1);
    assert.deepEqual(r.quality_reason_codes, ["incomplete_or_unknown_codeql_scope"]);
  }
});
// Shape observed from pinned codeql-action 33d7b85 (v4.39.3) analyze.ts + CLI 2.27.4
// interpret-results: full analysis OMITS incrementalMode (flag only added for
// diff-informed/overlay). Synthetic values only; no real findings or paths.
function actionProfile(language = "javascript-typescript") {
  const pack = language === "python" ? "python" : "javascript", prefix = language === "python" ? "py" : "js";
  return { version: "2.1.0", runs: [{
    tool: { driver: { name: "CodeQL", organization: "GitHub", semanticVersion: "2.27.4", notifications: [], rules: [] },
      extensions: [
        { name: `codeql/${pack}-queries`, semanticVersion: "0.0.0-synthetic", rules: [
          { id: `${prefix}/synthetic-error-rule`, defaultConfiguration: { enabled: true, level: "error" }, properties: { "security-severity": "7.5" } },
          { id: `${prefix}/synthetic-warning-rule`, defaultConfiguration: { enabled: true, level: "warning" } }],
          notifications: [{ id: `${prefix}/baseline/expected-extracted-files`, defaultConfiguration: { enabled: true } },
            { id: `${prefix}/diagnostics/successfully-extracted-files`, defaultConfiguration: { enabled: true } }] },
        { name: `codeql/${pack}-all`, semanticVersion: "0.0.0-synthetic" },
        { name: "codeql/threat-models", semanticVersion: "0.0.0-synthetic" }] },
    invocations: [{ executionSuccessful: true, toolExecutionNotifications: [
      { message: { text: "" }, level: "none", descriptor: { id: `${prefix}/baseline/expected-extracted-files`, index: 0, toolComponent: { index: 0 } },
        locations: [{ physicalLocation: { artifactLocation: { uri: "pilots/action-boundary/" + CODEQL_SCOPE[language][0], index: 0 } } }] }] }],
    artifacts: CODEQL_SCOPE[language].map((name, index) => ({ location: { uri: "pilots/action-boundary/" + name, index } })),
    results: [
      { ruleId: `${prefix}/synthetic-error-rule`, rule: { id: `${prefix}/synthetic-error-rule`, index: 0, toolComponent: { index: 0 } }, message: { text: "SYNTHETIC_CANARY finding" },
        partialFingerprints: { primaryLocationLineHash: "0000000000000000:1" }, locations: [{ physicalLocation: { artifactLocation: { uri: "pilots/action-boundary/" + CODEQL_SCOPE[language][0], index: 0 } } }] },
      { ruleId: `${prefix}/synthetic-warning-rule`, rule: { id: `${prefix}/synthetic-warning-rule`, index: 1, toolComponent: { index: 0 } }, message: { text: "SYNTHETIC_CANARY finding" } }],
    automationDetails: { id: `/language:${language}/` },
    properties: { "semmle.formatSpecifier": "sarif-latest", codeqlConfigSummary: { disableDefaultQueries: false, queries: [{ type: "builtinSuite", uses: "security-extended" }] } }
  }] };
}
for (const language of ["javascript-typescript", "python"]) test(`genuine pinned-Action full-analysis shape is accepted with findings retained (${language})`, () => {
  const r = summarizeCodeql(actionProfile(language), language);
  assert.equal(r.analysis_quality_valid, true); assert.deepEqual(r.quality_reason_codes, []); assert.deepEqual(r.scan_modes, ["full_action_default"]);
  assert.equal(r.findings_count, 2); assert.deepEqual(r.findings_by_level, { error: 1, warning: 1, note: 0, none: 0 });
  assert.equal(r.security_clean, false); // Findings are reported, never suppressed; they do not by themselves fail quality.
  const explicit = actionProfile(language); explicit.runs[0].properties.incrementalMode = "none";
  assert.equal(summarizeCodeql(explicit, language).analysis_quality_valid, true);
});
const profileQualityMutations = {
  incomplete_or_unknown_codeql_scope: [s => { s.runs[0].properties.incrementalMode = "diff-informed"; }, s => { s.runs[0].properties.incrementalMode = "overlay"; }],
  diff_informed_codeql_extension: [s => { s.runs[0].tool.extensions.push({ name: "codeql-action/pr-diff-range" }); }],
  unexpected_codeql_cli_version: [s => { s.runs[0].tool.driver.semanticVersion = "2.27.3"; }, s => { s.runs[0].tool.driver.semanticVersion = "2.27.4-rc1"; },
    s => { delete s.runs[0].tool.driver.semanticVersion; s.runs[0].tool.driver.version = "2.99.0"; }],
  extraction_failure_diagnostic: [s => { s.runs[0].tool.extensions[0].notifications.push({ id: "js/parse-error" }); s.runs[0].invocations[0].toolExecutionNotifications.push(notification("js/parse-error", { level: "warning" })); }],
  error_level_notification: [s => { s.runs[0].invocations[0].toolExecutionNotifications.push({ message: { text: "SYNTHETIC_CANARY" }, level: "error" }); }],
  required_artifacts_missing: [s => { s.runs[0].artifacts.pop(); }, s => { s.runs[0].artifacts = []; }]
};
for (const [code, list] of Object.entries(profileQualityMutations)) list.forEach((mutate, i) => test(`Action-profile quality rejection ${code} #${i}`, () => {
  const s = actionProfile(); mutate(s); const r = summarize(s);
  assert.equal(r.analysis_quality_valid, false); assert.ok(r.quality_reason_codes.includes(code), JSON.stringify(r.quality_reason_codes));
  assert.equal(r.findings_count, 2); // Findings are preserved on every rejection path.
}));
const profileThrowMutations = {
  not_codeql_analysis: [s => { s.runs[0].tool.driver.name = "NotCodeQL"; }, s => { delete s.runs[0].tool.driver; }, s => { delete s.runs[0].tool; }],
  missing_codeql_version: [s => { delete s.runs[0].tool.driver.semanticVersion; }, s => { s.runs[0].tool.driver.semanticVersion = ""; }],
  missing_security_extended_suite: [s => { s.runs[0].properties.codeqlConfigSummary.queries = [{ type: "builtinSuite", uses: "security-and-quality" }]; },
    s => { s.runs[0].properties.codeqlConfigSummary.queries = [{ type: "builtinSuite", uses: "default" }]; },
    s => { s.runs[0].properties.codeqlConfigSummary.queries = []; }, s => { delete s.runs[0].properties.codeqlConfigSummary; }, s => { delete s.runs[0].properties; }],
  missing_codeql_sarif_runs: [s => { s.runs = []; }, s => { s.version = "2.0.0"; }],
  unsupported_external_codeql_report: [s => { s.runs[0].externalPropertyFileReferences = { results: [{ itemCount: 41 }] }; }],
  unsuccessful_codeql_invocation: [s => { s.runs[0].invocations[0].executionSuccessful = false; }, s => { s.runs[0].invocations = []; }],
  missing_codeql_results: [s => { delete s.runs[0].results; }],
  missing_expected_language_rules: [s => { s.runs[0].tool.extensions[0].rules = []; s.runs[0].results = []; }],
  unresolved_codeql_descriptor_reference: [s => { s.runs[0].results[0].ruleId = "js/forged-rule"; s.runs[0].results[0].rule.id = "js/forged-rule"; }]
};
for (const [code, list] of Object.entries(profileThrowMutations)) list.forEach((mutate, i) => test(`Action-profile fail-closed ${code} #${i}`, () => {
  const s = actionProfile(); mutate(s); assert.throws(() => summarize(s), new RegExp(code));
}));
test("Action-profile end-to-end CLI pair publishes only aggregate counts and enum reason codes", () => withFile(dir => {
  const statusScript = new URL("../scripts/summarize-codeql-status.mjs", import.meta.url).pathname;
  const pair = sarif => { fs.writeFileSync(path.join(dir, "javascript.sarif"), JSON.stringify(sarif));
    const c = spawnSync(process.execPath, [checker, dir, "javascript-typescript"], { encoding: "utf8", timeout: 10000 });
    fs.writeFileSync(path.join(dir, "review.json"), c.stdout); fs.writeFileSync(path.join(dir, "error.json"), c.stderr);
    const p = spawnSync(process.execPath, [statusScript, path.join(dir, "review.json"), "javascript-typescript", path.join(dir, "error.json")], { encoding: "utf8", timeout: 10000 });
    assert.doesNotMatch(p.stdout + p.stderr, /SYNTHETIC_CANARY|pilots\/|primaryLocationLineHash/); return { c, p, out: JSON.parse(p.stdout) }; };
  let r = pair(actionProfile()); assert.equal(r.c.status, 0); assert.equal(r.p.status, 0);
  assert.deepEqual(r.out, { protocol: "aml-codeql-public-status/1", language: "javascript-typescript", analysis_quality_valid: true, findings_count: 2,
    findings_by_level: { error: 1, warning: 1, note: 0, none: 0 }, quality_reason_codes: [] });
  const partial = actionProfile(); partial.runs[0].properties.incrementalMode = "diff-informed";
  r = pair(partial); assert.equal(r.p.status, 1); assert.equal(r.out.findings_count, 2); assert.deepEqual(r.out.quality_reason_codes, ["incomplete_or_unknown_codeql_scope"]);
  const foreign = actionProfile(); foreign.runs[0].tool.driver.name = "SYNTHETIC_CANARY";
  r = pair(foreign); assert.equal(r.c.status, 1); assert.equal(r.p.status, 1); assert.equal(r.out.findings_count, null);
  assert.deepEqual(r.out.quality_reason_codes, ["invalid_status_input", "validator_not_codeql_analysis"]);
}));
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
