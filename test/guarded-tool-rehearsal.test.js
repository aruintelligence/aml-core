import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import { assertGuardedToolRehearsal, buildGuardedToolRehearsal, listGuardedToolCases, parseGuardedToolArgs, selectGuardedToolCase } from "../pilots/action-boundary/guarded-tool-rehearsal.mjs";

test("checked-in browser examples come from the live host adapter rehearsal", async () => {
  const report = await buildGuardedToolRehearsal();
  assertGuardedToolRehearsal(report);
  const published = JSON.parse(readFileSync(new URL("../docs/guarded-tool-rehearsal.json", import.meta.url), "utf8"));
  assert.deepEqual(published, report);
  for (const item of report.cases) {
    if (item.attempts.every(attempt => attempt.execution_status === "blocked")) {
      assert.equal(item.callback_count, 0, item.id);
    }
  }
  const reused = report.cases.find(item => item.id === "approval_reused");
  assert.equal(reused.attempts.length, 2);
  assert.equal(reused.claim_attempts, 2);
  assert.equal(reused.claims_consumed, 1);
  assert.equal(reused.callback_count, 1);
  const declined = report.cases.find(item => item.id === "approval_declined");
  assert.equal(declined.approval_requests, 1);
  assert.equal(declined.claim_attempts, 0);
  assert.equal(declined.callback_count, 0);
  assert.deepEqual(declined.attempts[0].host_hook_events,
    ["Approval requested", "Fixture approval declined"]);
  const revoked = report.cases.find(item => item.id === "claim_revoked");
  assert.equal(revoked.claims_consumed, 1);
  assert.equal(revoked.callback_count, 0);
  const claimError = report.cases.find(item => item.id === "claim_hook_unknown");
  assert.equal(claimError.attempts[0].reason, "approval_consume_error");
  assert.equal(claimError.claims_consumed, 1);
  assert.equal(claimError.callback_count, 0);
  const uncertain = report.cases.find(item => item.id === "callback_unknown");
  assert.equal(uncertain.attempts[0].execution_status, "unknown");
  assert.equal(uncertain.callback_count, 1);
});

test("one selected case keeps the same observed receipt and callback count", async () => {
  const report = await buildGuardedToolRehearsal();
  const selected = selectGuardedToolCase(report, "approval_reused");
  assert.equal(selected.case.id, "approval_reused");
  assert.deepEqual(selected.case.attempts.map(attempt => attempt.execution_status), ["dispatched", "blocked"]);
  assert.equal(selected.case.callback_count, 1);
  assert.throws(() => selectGuardedToolCase(report, "unlisted"), RangeError);
});

test("case list prints each fixture ID and its ordered receipt statuses", async () => {
  const report = await buildGuardedToolRehearsal();
  const listed = listGuardedToolCases(report);
  assert.equal(listed.split("\n").filter(Boolean).length, 11);
  assert.match(listed, /^approval_declined\tblocked$/m);
  assert.match(listed, /^approval_reused\tdispatched -> blocked$/m);
  assert.match(listed, /^claim_hook_unknown\tblocked$/m);
  assert.match(listed, /^callback_unknown\tunknown$/m);
});

test("CLI rejects extra, missing, unknown, and conflicting arguments", () => {
  assert.deepEqual(parseGuardedToolArgs([]), { option: undefined, caseId: undefined });
  assert.deepEqual(parseGuardedToolArgs(["--list"]), { option: "--list", caseId: undefined });
  assert.deepEqual(parseGuardedToolArgs(["--case", "claim_revoked"]),
    { option: "--case", caseId: "claim_revoked" });
  for (const args of [
    ["--check", "extra"], ["--write", "extra"], ["--list", "extra"],
    ["--case"], ["--case", "unlisted"], ["--case", "approved_route", "extra"],
    ["--list", "--write"], ["--unknown"]
  ]) {
    assert.throws(() => parseGuardedToolArgs(args),
      /Use no argument.*--list.*--case/, args.join(" "));
  }
});
