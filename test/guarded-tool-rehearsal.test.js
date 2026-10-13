import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import { assertGuardedToolRehearsal, buildGuardedToolRehearsal, selectGuardedToolCase } from "../pilots/action-boundary/guarded-tool-rehearsal.mjs";

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
  const revoked = report.cases.find(item => item.id === "claim_revoked");
  assert.equal(revoked.claims_consumed, 1);
  assert.equal(revoked.callback_count, 0);
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
