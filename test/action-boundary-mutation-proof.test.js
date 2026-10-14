import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import { buildDispatchMutants, resourceSubstitutionProbe } from "../pilots/action-boundary/dispatch-mutants.mjs";

const checkedIn = JSON.parse(readFileSync(
  new URL("../docs/action-dispatch-mutants.json", import.meta.url), "utf8"));

test("selected source mutations match the checked-in, source-bound report", async () => {
  assert.deepEqual(await buildDispatchMutants(), checkedIn);
  assert.deepEqual(checkedIn.summary, { selected_mutants: 9,
    matrix_detected: 7, tuple_detected: 3, tuple_only_detected: 2,
    combined_detected: 9, undetected: 0 });
  assert.equal(checkedIn.matrix_vectors, 384);
  assert.equal(checkedIn.tuple_cases, 8);
  assert.deepEqual(checkedIn.mutations.filter(row => row.matrix_changed_rows === 0).map(row => row.id),
    ["tool_wildcard", "effect_wildcard"]);
  assert.deepEqual(checkedIn.mutations.slice(-3).map(row =>
    [row.id, row.matrix_changed_rows, row.tuple_changed_cases, row.first_changed_tuple.index]),
  [["resource_wildcard", 192, 1, 1], ["tool_wildcard", 0, 1, 4],
    ["effect_wildcard", 0, 1, 2]]);
  assert.equal(checkedIn.mutations.find(row => row.id === "resource_wildcard").resource_probe_result.callback_count, 1);
});

test("a rule for another resource never reaches the host callback", async () => {
  assert.deepEqual(await resourceSubstitutionProbe(), {
    execution_status: "blocked", reason: "no_exact_rule",
    policy_decision: "deny", callback_count: 0
  });
});
