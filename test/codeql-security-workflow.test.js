import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { CODEQL_SCOPE, summarizeCodeql, reviewDirectory } from "../scripts/check-codeql-sarif.mjs";

const root = fileURLToPath(new URL("../", import.meta.url));
const reporter = path.join(root, "scripts/check-codeql-sarif.mjs");
function synthetic(language = "javascript-typescript") {
  const prefix = language === "python" ? "py" : "js";
  return { version: "2.1.0", runs: [{
    tool: { driver: { name: "CodeQL", semanticVersion: "0.0.0-synthetic-test" }, extensions: [{
      name: `codeql/${language}-queries`, rules: [{ id: `${prefix}/synthetic-rule`, defaultConfiguration: { level: "error" }, properties: { "security-severity": "7.8" } }],
      notifications: [{ id: "synthetic/extraction-error", defaultConfiguration: { level: "error" } }]
    }] },
    invocations: [{ executionSuccessful: true }], results: [],
    artifacts: CODEQL_SCOPE[language].map(name => ({ location: { uri: `pilots/action-boundary/${name}` } })),
    properties: { incrementalMode: "none", codeqlConfigSummary: { queries: [{ type: "builtinSuite", uses: "security-extended" }] } }
  }] };
}
function directory(run) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "aml-synthetic-sarif-"));
  try { return run(dir); } finally { fs.rmSync(dir, { recursive: true, force: true }); }
}
const cli = (dir, language = "javascript-typescript") => spawnSync(process.execPath, [reporter, dir, language], { encoding: "utf8", timeout: 10_000 });

test("SARIF validator accepts synthetic JavaScript metadata, not proof of a real scan", () => {
  const r = summarizeCodeql(synthetic(), "javascript-typescript");
  assert.equal(r.analysis_quality_valid, true); assert.equal(r.findings_count, 0); assert.equal(r.security_clean, true);
});
test("SARIF validator recognizes synthetic Python rule scope", () => {
  assert.equal(summarizeCodeql(synthetic("python"), "python").analysis_quality_valid, true);
});
test("SARIF findings inherit rule default severity rather than all becoming warnings", () => {
  const s = synthetic(); s.runs[0].results = [{ message: { text: "Synthetic finding" }, ruleId: "js/synthetic-rule" }];
  const r = summarizeCodeql(s, "javascript-typescript");
  assert.equal(r.findings_by_level.error, 1); assert.equal(r.findings[0].security_severity, "7.8");
  assert.equal(r.analysis_quality_valid, true); assert.equal(r.security_clean, false);
});
test("SARIF explicit result level overrides its rule default", () => {
  const s = synthetic(); s.runs[0].results = [{ message: { text: "Synthetic finding" }, ruleId: "js/synthetic-rule", level: "warning" }];
  assert.equal(summarizeCodeql(s, "javascript-typescript").findings_by_level.warning, 1);
});
test("SARIF accepted suppressions are still visible, never silently excluded", () => {
  const s = synthetic(); s.runs[0].results = [{ message: { text: "Synthetic finding" }, ruleId: "js/synthetic-rule", suppressions: [{ status: "accepted", kind: "inSource" }] }];
  const r = summarizeCodeql(s, "javascript-typescript"); assert.equal(r.findings_count, 1); assert.equal(r.findings[0].suppressions_present, true);
});
test("SARIF rejects a tool that is not CodeQL", () => {
  const s = synthetic(); s.runs[0].tool.driver.name = "not-CodeQL";
  assert.throws(() => summarizeCodeql(s, "javascript-typescript"), /not_codeql_analysis/);
});
test("SARIF requires the requested language and security-extended suite", () => {
  assert.throws(() => summarizeCodeql(synthetic(), "python"), /missing_expected_language_rules/);
  const s = synthetic(); s.runs[0].properties.codeqlConfigSummary.queries = [{ uses: "default" }];
  assert.throws(() => summarizeCodeql(s, "javascript-typescript"), /missing_security_extended_suite/);
});
test("SARIF missing or failed invocations cannot become analysis success", () => {
  for (const invocations of [[], [{ executionSuccessful: false }], [{}]]) {
    const s = synthetic(); s.runs[0].invocations = invocations;
    assert.throws(() => summarizeCodeql(s, "javascript-typescript"), /unsuccessful_codeql_invocation/);
  }
});
test("SARIF missing required auth artifacts fails quality, presence alone is not extraction proof", () => {
  const s = synthetic(); s.runs[0].artifacts.pop();
  const r = summarizeCodeql(s, "javascript-typescript"); assert.equal(r.analysis_quality_valid, false); assert.equal(r.required_artifacts_missing.length, 1);
});
test("SARIF explicit extraction errors fail quality even with executionSuccessful true", () => {
  const s = synthetic(); s.runs[0].invocations[0].toolExecutionNotifications = [{ message: { text: "Synthetic extraction failure" }, level: "error", descriptor: { id: "synthetic/extraction-error" } }];
  const r = summarizeCodeql(s, "javascript-typescript"); assert.equal(r.analysis_quality_valid, false); assert.equal(r.extraction_or_configuration_errors.length, 1);
});
test("SARIF diagnostic descriptor default error is respected when level omitted", () => {
  const s = synthetic(); s.runs[0].invocations[0].toolConfigurationNotifications = [{ message: { text: "Synthetic extraction failure" }, descriptor: { id: "synthetic/extraction-error" } }];
  assert.equal(summarizeCodeql(s, "javascript-typescript").analysis_quality_valid, false);
});
test("SARIF malformed schema, missing version, unknown rules and invalid levels reject", () => {
  assert.throws(() => summarizeCodeql({}, "javascript-typescript"), /missing_codeql_sarif_runs/);
  assert.throws(() => summarizeCodeql(synthetic(), "unknown"), /unsupported_codeql_language/);
  for (const mutate of [s => delete s.runs[0].tool.driver.semanticVersion,
    s => delete s.runs[0].results,
    s => { s.runs[0].results = [{ message: { text: "Synthetic finding" }, ruleId: "unknown" }]; },
    s => { s.runs[0].results = [{ message: { text: "Synthetic finding" }, ruleId: "js/synthetic-rule", level: "bogus" }]; },
    s => { s.runs[0].invocations[0].toolExecutionNotifications = "not-an-array"; },
    s => { s.runs[0].invocations[0].toolConfigurationNotifications = [{ level: "bogus" }]; }]) {
    const s = synthetic(); mutate(s); assert.throws(() => summarizeCodeql(s, "javascript-typescript"));
  }
});
test("SARIF CLI missing output fails rather than inventing zero findings", () => directory(dir => {
  const r = cli(dir); assert.equal(r.status, 1); assert.match(r.stderr, /expected_exactly_one_language_sarif/);
}));
test("SARIF CLI malformed output fails and multiple language artifacts cannot mix", () => directory(dir => {
  fs.writeFileSync(path.join(dir, "one.sarif"), "{"); assert.equal(cli(dir).status, 1);
  fs.writeFileSync(path.join(dir, "one.sarif"), JSON.stringify(synthetic()));
  fs.writeFileSync(path.join(dir, "two.sarif"), JSON.stringify(synthetic()));
  assert.throws(() => reviewDirectory(dir, "javascript-typescript"), /expected_exactly_one_language_sarif/);
}));
test("SARIF CLI extraction failure preserves structured report and exits nonzero", () => directory(dir => {
  const s = synthetic(); s.runs[0].artifacts = []; fs.writeFileSync(path.join(dir, "result.sarif"), JSON.stringify(s));
  const r = cli(dir); assert.equal(r.status, 1); assert.equal(JSON.parse(r.stdout).analysis_quality_valid, false);
}));
test("SARIF CLI synthetic valid metadata exits zero without pretending a scanner ran", () => directory(dir => {
  fs.writeFileSync(path.join(dir, "result.sarif"), JSON.stringify(synthetic()));
  const r = cli(dir); assert.equal(r.status, 0); assert.equal(JSON.parse(r.stdout).codeql_versions[0], "0.0.0-synthetic-test");
}));
test("CodeQL workflow uses normal development/main PR triggers with no path filter", () => {
  const text = fs.readFileSync(path.join(root, ".github/workflows/codeql.yml"), "utf8").replace(/^\s*#.*$/gm, "");
  const events = text.split("\non:\n")[1].split("\npermissions:")[0];
  assert.match(events, /pull_request:/); assert.match(events, /push:/); assert.match(events, /schedule:/);
  assert.equal((events.match(/- operation-aml\/grant-store-integrity-20261104/g) ?? []).length, 2);
  assert.equal((events.match(/- main/g) ?? []).length, 2);
  assert.match(events, /types: \[opened, synchronize, reopened, ready_for_review, edited\]/);
  assert.doesNotMatch(events, /paths(?:-ignore)?:|pull_request_target|workflow_run/);
});
test("CodeQL workflow keeps read-only permissions and pins both actual scanner actions", () => {
  const text = fs.readFileSync(path.join(root, ".github/workflows/codeql.yml"), "utf8").replace(/^\s*#.*$/gm, "");
  assert.match(text, /permissions:\n  contents: read\n  actions: read/);
  assert.doesNotMatch(text, /security-events:|id-token:|: write|secrets\.|continue-on-error|self-hosted/);
  assert.equal((text.match(/persist-credentials: false/g) ?? []).length, 1);
  assert.equal((text.match(/github\/codeql-action\/(?:init|analyze)@33d7b85da1a04171e211befe2c739303b9a4c066/g) ?? []).length, 2);
  assert.match(text, /language: \[javascript-typescript, python\]/); assert.match(text, /build-mode: none/);
  assert.match(text, /queries: security-extended/); assert.match(text, /upload: never/);
  assert.doesNotMatch(text, /upload: false|upload: true|skip-queries/);
  assert.match(text, /upload-database: false/); assert.match(text, /dependency-caching: none/); assert.match(text, /trap-caching: false/);
  assert.doesNotMatch(text, /upload-artifact|retention-days:|if-no-files-found:/); assert.match(text, /fail-fast: false/);
  assert.match(text, /> codeql-private-review\.json 2> codeql-private-error\.json/);
  assert.match(text, /node scripts\/summarize-codeql-status\.mjs/);
});
test("pilot CI explicitly executes both authorization wrappers and SARIF/workflow regression tests", () => {
  const text = fs.readFileSync(path.join(root, ".github/workflows/action-contract-pilot-003.yml"), "utf8");
  for (const file of ["action-boundary-atomic-authorized-execution.test.js", "action-boundary-atomic-review-regressions.test.js",
    "action-boundary-authorization-paths.test.js", "codeql-security-workflow.test.js",
    "codeql-sarif-integrity.test.js", "action-observed-callback-confinement.test.js", "codeql-public-status.test.js"]) assert.ok(text.includes("test/" + file));
  assert.match(text, /run: node --test --test-timeout=120000\n/);
  assert.match(text, /unittest discover -s test -p test_python_boundary\.py/);
});
test("repository workflow permission guard remains unchanged and passes", () => {
  const r = spawnSync(process.execPath, [path.join(root, "scripts/check-workflow-safety.mjs")], { cwd: root, encoding: "utf8", timeout: 10_000 });
  assert.equal(r.status, 0, r.stderr); assert.equal(JSON.parse(r.stdout).valid, true);
});


test("CodeQL includes authored long-line scripts instead of accepting minification skips", () => {
  const workflow = fs.readFileSync(path.join(root, ".github/workflows/codeql.yml"), "utf8");
  assert.match(workflow, /CODEQL_EXTRACTOR_JAVASCRIPT_ALLOW_MINIFIED_FILES: "true"/);
});
