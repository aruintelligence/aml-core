import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import test from "node:test";
import { chooseRehearsalCase, nextRehearsalCaseIndex, rehearsalCasePayload, rehearsalCaseUrl, visibleRehearsalCaseIds } from "../docs/agent-start.js";
import { selectGuardedToolCase } from "../pilots/action-boundary/guarded-tool-rehearsal.mjs";

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
  assert.match(page, /id="case-picker"[^>]*role="radiogroup"/);
  assert.match(page, /<label for="case-search">Find a case<\/label>/);
  assert.match(page, /id="case-search-status" role="status" aria-live="polite"/);
  assert.match(page, /id="case-panel" role="region" aria-labelledby="case-title" tabindex="0"/);
  assert.match(page, /id="route-label"/);
  assert.match(page, /href="#case-title">Jump to selected result/);
  assert.match(page, /Every callback is a fixture/);
  assert.match(page, /consumeApproval: \(input, context\) => hostConsumeGrantOnce/);
  assert.match(page, /An <code>unknown<\/code> receipt does not mean no side effect occurred/);
  assert.match(page, /A claim-hook error can leave a grant spent/);
  assert.match(page, /An approval-hook error can leave host authorization state changed/);
});

test("case radios expose one checked choice and explicit receipt meanings", () => {
  const script = readFileSync(new URL("../docs/agent-start.js", import.meta.url), "utf8");
  assert.match(script, /setAttribute\("role", "radio"\)/);
  assert.match(script, /setAttribute\("aria-checked", String\(selected\)\)/);
  assert.match(script, /Local fixture callback returned; external delivery is unverified/);
  assert.match(script, /Local fixture callback threw; a side effect may have occurred/);
});

test("the page versions its script and the script versions its report by content", () => {
  const page = readFileSync(new URL("../docs/agent-start.html", import.meta.url), "utf8");
  const script = readFileSync(new URL("../docs/agent-start.js", import.meta.url), "utf8");
  const reportText = readFileSync(new URL("../docs/guarded-tool-rehearsal.json", import.meta.url), "utf8");
  const fingerprint = value => createHash("sha256").update(value).digest("hex").slice(0, 12);
  assert.ok(script.includes(`guarded-tool-rehearsal.json?v=${fingerprint(reportText)}`),
    "Report URL must change when the generated report changes");
  assert.ok(page.includes(`agent-start.js?v=${fingerprint(script)}`),
    "Script URL must change when the builder script changes");
});

test("keyboard case navigation wraps and keeps other keys available", () => {
  const count = report.cases.length;
  assert.equal(nextRehearsalCaseIndex("ArrowRight", count - 1, count), 0);
  assert.equal(nextRehearsalCaseIndex("ArrowDown", 2, count), 3);
  assert.equal(nextRehearsalCaseIndex("ArrowLeft", 0, count), count - 1);
  assert.equal(nextRehearsalCaseIndex("ArrowUp", 2, count), 1);
  assert.equal(nextRehearsalCaseIndex("Home", 5, count), 0);
  assert.equal(nextRehearsalCaseIndex("End", 5, count), count - 1);
  assert.equal(nextRehearsalCaseIndex("Enter", 5, count), null);
});

test("case search keeps the selected choice visible and narrows keyboard order", () => {
  const claim = visibleRehearsalCaseIds(report, "claim revoked", "mapper_write_error");
  assert.ok(claim.includes("mapper_write_error"));
  assert.ok(claim.includes("claim_revoked"));
  assert.ok(!claim.includes("host_allow"));
  assert.deepEqual(visibleRehearsalCaseIds(report, "mapper error", "claim_revoked"),
    ["mapper_mutated", "mapper_write_error", "claim_revoked"]);
  assert.deepEqual(visibleRehearsalCaseIds(report, "no such fixture", "mapper_write_error"),
    ["mapper_write_error"]);
  assert.equal(visibleRehearsalCaseIds(report, " ", "claim_revoked").length, report.cases.length);
  const position = claim.indexOf("mapper_write_error");
  assert.equal(claim[nextRehearsalCaseIndex("ArrowRight", position, claim.length)], "claim_revoked");
});

test("copied fixture payload matches the CLI case with its provenance and scope", () => {
  assert.deepEqual(rehearsalCasePayload(report, "unknown_then_replay"),
    selectGuardedToolCase(report, "unknown_then_replay"));
  assert.match(rehearsalCasePayload(report, "unknown_then_replay").scope,
    /No message, human approval, provider call, or delivery evidence/);
  assert.throws(() => rehearsalCasePayload(report, "unlisted"), RangeError);
});
