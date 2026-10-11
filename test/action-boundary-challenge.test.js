import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { prepareCase, checkCase, diagnoseCase, selectChallengeCases, challengeScope } from "../conformance/action-boundary-challenge-core.js";
import { runReferenceCase } from "../pilots/action-boundary/challenge-reference-adapter.mjs";

const manifest = JSON.parse(readFileSync(new URL("../conformance/action-boundary-challenge.json", import.meta.url)));
const vectors = JSON.parse(readFileSync(new URL("../pilots/action-boundary/vectors.json", import.meta.url)));

test("the reference boundary satisfies every published host scenario", async () => {
  assert.equal(manifest.cases.length, 13);
  for (const row of manifest.cases) {
    const output = await runReferenceCase(prepareCase(row, vectors));
    assert.deepEqual(checkCase(row, output, { status: 0 }, vectors), [], row.id);
  }
});

test("the challenge catches fabricated dispatch and mutated arguments", async () => {
  const denied = manifest.cases.find(row => row.id === "changed-destination");
  const deniedOutput = await runReferenceCase(prepareCase(denied, vectors));
  deniedOutput.tool_calls = 1;
  deniedOutput.executed_proposal = structuredClone(deniedOutput.plan);
  assert.deepEqual(checkCase(denied, deniedOutput, { status: 0 }, vectors),
    ["tool_calls", "executed_proposal"]);

  const mutation = manifest.cases.find(row => row.id === "mutated-while-awaiting");
  const mutationOutput = await runReferenceCase(prepareCase(mutation, vectors));
  mutationOutput.executed_proposal.arguments.body = "MUTATED";
  assert.deepEqual(checkCase(mutation, mutationOutput, { status: 0 }, vectors),
    ["executed_proposal"]);
});

test("a broken process or malformed output cannot produce a PASS", () => {
  const row = manifest.cases[0];
  const failures = checkCase(row, null, { status: 1, error: { code: "ENOENT" } }, vectors);
  assert.ok(failures.includes("process_error:ENOENT"));
  assert.ok(failures.includes("exit_code:1"));
  assert.ok(failures.includes("plan"));
  assert.ok(failures.includes("receipt"));
});

test("field diagnostics identify a wrong decision and never erase machine failure codes", async () => {
  const row = manifest.cases.find(item => item.id === "changed-destination");
  const output = await runReferenceCase(prepareCase(row, vectors));
  output.plan.decision = "allow";
  output.tool_calls = 1;
  assert.deepEqual(checkCase(row, output, { status: 0 }, vectors), ["plan", "tool_calls"]);
  assert.deepEqual(diagnoseCase(row, output, vectors).map(item => item.field),
    ["plan.decision", "tool_calls"]);
  assert.deepEqual(diagnoseCase(row, output, vectors)[0],
    { field: "plan.decision", expected: '"deny"', actual: '"allow"' });
});

test("focused case selection preserves an honest partial scope", () => {
  assert.deepEqual(selectChallengeCases(manifest.cases, "changed-destination").map(row => row.id),
    ["changed-destination"]);
  assert.deepEqual(selectChallengeCases(manifest.cases), manifest.cases);
  assert.throws(() => selectChallengeCases(manifest.cases, "not-a-case"), /Unknown case/);
  assert.deepEqual(challengeScope("changed-destination", true),
    { case_scope: "single", selected_case: "changed-destination", full_challenge_passed: false });
  assert.deepEqual(challengeScope(null, true),
    { case_scope: "full", selected_case: null, full_challenge_passed: true });
});
