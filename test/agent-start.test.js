import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import { chooseRehearsalCase, rehearsalCaseUrl } from "../docs/agent-start.js";

const report = JSON.parse(readFileSync(new URL("../docs/guarded-tool-rehearsal.json", import.meta.url), "utf8"));

test("first-contact route opens the matching host case and an explicit case stays shareable", () => {
  assert.equal(chooseRehearsalCase(report, null, "outside"), "changed_destination");
  assert.equal(chooseRehearsalCase(report, null, "team"), "approved_route");
  assert.equal(chooseRehearsalCase(report, "approval_reused", "team"), "approval_reused");
  assert.equal(chooseRehearsalCase(report, "claim_hook_unknown", "team"), "claim_hook_unknown");
  assert.equal(chooseRehearsalCase(report, "unlisted", "outside"), "changed_destination");
  const url = rehearsalCaseUrl("https://example.test/agent-start.html?recipient=team#steps", "policy_revoked", report);
  assert.equal(url, "https://example.test/agent-start.html?recipient=team&case=policy_revoked#rehearsal");
  assert.throws(() => rehearsalCaseUrl("https://example.test/agent-start.html", "unlisted", report), RangeError);
});

test("the page labels the report as a fixture and offers the exact recheck command", () => {
  const page = readFileSync(new URL("../docs/agent-start.html", import.meta.url), "utf8");
  assert.match(page, /guarded-tool-rehearsal\.mjs --check/);
  assert.match(page, /id="case-picker"/);
  assert.match(page, /Every callback is a fixture/);
  assert.match(page, /An <code>unknown<\/code> receipt does not mean no side effect occurred/);
  assert.match(page, /A claim-hook error can leave a grant spent/);
});
