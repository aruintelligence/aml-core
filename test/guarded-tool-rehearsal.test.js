import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import { assertGuardedToolRehearsal, buildGuardedToolRehearsal } from "../pilots/action-boundary/guarded-tool-rehearsal.mjs";

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
  assert.equal(reused.callback_count, 1);
  const uncertain = report.cases.find(item => item.id === "callback_unknown");
  assert.equal(uncertain.attempts[0].execution_status, "unknown");
  assert.equal(uncertain.callback_count, 1);
});
