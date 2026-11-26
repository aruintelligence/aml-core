// Directive 010: committed CodeQL data-flow queries close six lexical-checker
// bypass categories. The corpus is data (tooling/codeql/authz-bypass-fixtures.json)
// so the intentionally vulnerable snippets are never shipped or scanned as code.
import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";

const corpus = JSON.parse(fs.readFileSync("tooling/codeql/authz-bypass-fixtures.json", "utf8"));
const CATEGORIES = ["call-argument", "container", "computed-property", "multiline", "cross-file", "go-alias-wrapper"];
// Directive 010 follow-up categories and the languages each must cover.
const FOLLOW_UP = { "map-container": ["javascript"], "reflect": ["javascript", "go"], "getattr": ["python"],
  "authorization-not-controlling": ["javascript", "python", "go"], "authorization-alternative": ["javascript", "python", "go"] };

test("fixture corpus covers every bypass category and has an authorized control per language", () => {
  const fx = Object.values(corpus.fixtures);
  for (const category of CATEGORIES) {
    assert.ok(fx.some(f => f.category === category && f.expect_flagged === true), category);
  }
  for (const category of CATEGORIES.filter(c => c !== "go-alias-wrapper")) {
    for (const language of ["javascript", "python"]) {
      assert.ok(fx.some(f => f.category === category && f.language === language), `${category} ${language}`);
    }
  }
  for (const language of ["javascript", "python", "go"]) {
    assert.ok(fx.some(f => f.language === language && f.expect_flagged === false), `control ${language}`);
    const q = `tooling/codeql/${language}/VerificationWithoutAuthorization.ql`;
    const text = fs.readFileSync(q, "utf8");
    assert.match(text, /@kind problem/);
    assert.match(text, new RegExp(`@id aml/${language === "javascript" ? "js" : language === "python" ? "py" : "go"}/verification-without-authorization`));
  }
});

test("fixture corpus covers the follow-up categories (Map, Reflect.get, getattr, non-controlling authorization)", () => {
  const fx = Object.values(corpus.fixtures);
  for (const [category, languages] of Object.entries(FOLLOW_UP)) {
    for (const language of languages) {
      assert.ok(fx.some(f => f.category === category && f.language === language && f.expect_flagged === true), `${category} ${language}`);
    }
  }
  assert.ok(fx.filter(f => f.expect_flagged === false).length >= 7, "authorized controls for the new constructs");
});

test("CI workflow runs the corpus and the gated repository scan with zero suppressions", () => {
  const text = fs.readFileSync(".github/workflows/codeql-authorization-dataflow.yml", "utf8").replace(/^\s*#.*$/gm, "");
  assert.match(text, /permissions:\n  contents: read\n  actions: read/);
  assert.doesNotMatch(text, /security-events:|id-token:|: write|secrets\.|continue-on-error|self-hosted|upload-artifact|paths(?:-ignore)?:/);
  assert.match(text, /persist-credentials: false/);
  assert.match(text, /github\/codeql-action\/init@33d7b85da1a04171e211befe2c739303b9a4c066/);
  assert.match(text, /run: node scripts\/check-authorization-dataflow\.mjs\n/);
  assert.match(text, /run: node scripts\/check-authorization-dataflow\.mjs --repo-gate audit\/AML_AUTHZ_DATAFLOW_REVIEW\.json\n/);
  assert.match(text, /pull_request:/); assert.match(text, /push:/);
  assert.doesNotMatch(text, /query-filters|exclude:|paths-ignore|\|\| true/);
});

test("repository gate: unreviewed, stale, unclassified alerts and source suppressions all fail", async () => {
  const { gateRepository, sourceSuppressions } = await import("../scripts/check-authorization-dataflow.mjs");
  const review = { schema: "aml-authz-dataflow-review/1", entries: [
    { language: "javascript", file: "a.js", code: "process.exit(r.valid ? 0 : 1);", class: "diagnostic-non-authorizing", why: "prints a diagnostic report only" }] };
  const alert = { file: "a.js", line: 1, code: "process.exit(r.valid ? 0 : 1);", message: "m" };
  assert.deepEqual(gateRepository({ javascript: [alert], python: [], go: [] }, review).failures, []);
  assert.match(gateRepository({ javascript: [alert, { ...alert, code: "other" }] }, review).failures.join(), /unreviewed alert/);
  assert.match(gateRepository({ javascript: [] }, review).failures.join(), /stale review entry/);
  const unclassified = { ...review, entries: [{ ...review.entries[0], class: "accepted-risk" }] };
  assert.match(gateRepository({ javascript: [alert] }, unclassified).failures.join(), /without a valid class/);
  assert.match(gateRepository({ javascript: [alert] }, review, ["x.js:3"]).failures.join(), /suppression comment refused/);
  assert.match(gateRepository({}, { schema: "x" }).failures.join(), /schema invalid/);
  assert.deepEqual(sourceSuppressions(), [], "no CodeQL/LGTM suppression comments in the repository");
  const reviewed = JSON.parse(fs.readFileSync("audit/AML_AUTHZ_DATAFLOW_REVIEW.json", "utf8"));
  assert.equal(reviewed.schema, "aml-authz-dataflow-review/1");
  assert.equal(gateRepository({}, reviewed).failures.filter(f => /without a valid class/.test(f)).length, 0);
});

test("data-flow check fails closed when the CodeQL CLI is unavailable", () => {
  const out = spawnSync(process.execPath, ["scripts/check-authorization-dataflow.mjs"], {
    encoding: "utf8", env: { ...process.env, CODEQL_CLI: "/nonexistent/codeql", PATH: path.dirname(process.execPath) }
  });
  assert.equal(out.status, 2, out.stderr);
  assert.match(out.stderr, /fails closed/);
});

const cli = process.env.CODEQL_CLI;
test("CodeQL queries flag every seeded bypass and no authorized control", { skip: cli ? false : "CODEQL_CLI not set: CodeQL fixture check skipped (run scripts/check-authorization-dataflow.mjs with CODEQL_CLI)", timeout: 1_800_000 }, async () => {
  const { checkFixtures } = await import("../scripts/check-authorization-dataflow.mjs");
  const results = checkFixtures(cli);
  const bad = results.filter(r => !r.ok);
  assert.deepEqual(bad.map(r => `${r.fixture}: flagged=${r.flagged} ${r.error ?? ""}`), []);
  assert.equal(results.length, Object.keys(corpus.fixtures).length);
});
