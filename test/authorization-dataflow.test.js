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
