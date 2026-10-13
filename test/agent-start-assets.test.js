import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import { versionAgentStartAssets } from "../scripts/refresh-agent-start-assets.mjs";

const report = readFileSync(new URL("../docs/guarded-tool-rehearsal.json", import.meta.url), "utf8");
const script = readFileSync(new URL("../docs/agent-start.js", import.meta.url), "utf8");
const page = readFileSync(new URL("../docs/agent-start.html", import.meta.url), "utf8");

test("current builder asset URLs match the report and script bytes", () => {
  const versioned = versionAgentStartAssets(report, script, page);
  assert.equal(versioned.script, script);
  assert.equal(versioned.page, page);
});

test("changing report bytes refreshes both URLs without touching other content", () => {
  const changedReport = report.replace("project-authored local Node simulation", "revised local fixture simulation");
  const versioned = versionAgentStartAssets(changedReport, script, page);
  assert.notEqual(versioned.script, script);
  assert.notEqual(versioned.page, page);
  assert.ok(versioned.script.includes(`guarded-tool-rehearsal.json?v=${versioned.reportHash}`));
  assert.ok(versioned.page.includes(`agent-start.js?v=${versioned.scriptHash}`));
  assert.equal(versionAgentStartAssets(changedReport, versioned.script, versioned.page).page, versioned.page);
});

test("missing or duplicated asset references fail instead of guessing", () => {
  assert.throws(() => versionAgentStartAssets(report, script.replace("guarded-tool-rehearsal.json?v=", "report.json?v="), page),
    /Expected one asset URL, found 0/);
  assert.throws(() => versionAgentStartAssets(report, script, page + page.match(/agent-start\.js\?v=[0-9a-f]{12}/)[0]),
    /Expected one asset URL, found 2/);
});
