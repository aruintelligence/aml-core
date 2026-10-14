import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import { buildDispatchMutants, resourceSubstitutionProbe } from "../pilots/action-boundary/dispatch-mutants.mjs";

const checkedIn = JSON.parse(readFileSync(
  new URL("../docs/action-dispatch-mutants.json", import.meta.url), "utf8"));

test("selected source mutations match the checked-in, source-bound report", async () => {
  assert.deepEqual(await buildDispatchMutants(), checkedIn);
  assert.deepEqual(checkedIn.summary, { selected_mutants: 7,
    matrix_detected: 7, additional_probe_detected: 0, undetected: 0 });
  assert.equal(checkedIn.matrix_vectors, 384);
  assert.deepEqual(checkedIn.mutations.filter(row => row.matrix_changed_rows === 0), []);
  assert.equal(checkedIn.mutations.at(-1).matrix_changed_rows, 192);
  assert.equal(checkedIn.mutations.at(-1).first_changed_vector.index, 192);
  assert.equal(checkedIn.mutations.at(-1).resource_probe_changed, true);
  assert.equal(checkedIn.mutations.at(-1).resource_probe_result.callback_count, 1);
});

test("a rule for another resource never reaches the host callback", async () => {
  assert.deepEqual(await resourceSubstitutionProbe(), {
    execution_status: "blocked", reason: "no_exact_rule",
    policy_decision: "deny", callback_count: 0
  });
});
