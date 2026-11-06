import test from "node:test";
import assert from "node:assert/strict";
import { probeCompleteStoreRollback } from "../pilots/action-boundary/file-grant-rollback-probe.mjs";

test("complete pre-claim store rollback revives a grant without an external anchor", async () => {
  const result = await probeCompleteStoreRollback();
  assert.equal(result.original_claim, true);
  assert.equal(result.ordinary_replay, false);
  assert.equal(result.after_rollback, true); // Preserved negative finding.
  assert.equal(result.external_effects_attempted, 0);
});
