import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { prepareCase, checkCase } from "../conformance/action-boundary-challenge-core.js";
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
