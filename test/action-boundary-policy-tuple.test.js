import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { buildPolicyTuple, tupleAxes } from "../pilots/action-boundary/policy-tuple.mjs";

const report = JSON.parse(readFileSync(new URL("../docs/action-policy-tuple.json", import.meta.url), "utf8"));
const oracle = fileURLToPath(new URL("../pilots/action-boundary/verify_policy_tuple.py", import.meta.url));
const verify = value => spawnSync("python3", [oracle, "-"], {
  input: JSON.stringify(value), encoding: "utf8"
});

test("the policy tuple covers all eight independent rule-binding combinations", async () => {
  assert.deepEqual(report, await buildPolicyTuple());
  assert.equal(report.rows.length, Object.values(tupleAxes).reduce((n, axis) => n * axis.length, 1));
  const result = verify(report);
  assert.equal(result.status, 0, result.stderr);
  assert.equal(JSON.parse(result.stdout).cases_verified, 8);
  assert.deepEqual(report.rows.map(row => row.callback_count), [1, 0, 0, 0, 0, 0, 0, 0]);
  for (const index of [1, 2, 4]) {
    assert.equal(report.rows[index].receipt.reason, "no_exact_rule");
    assert.equal(report.rows[index].receipt.execution_status, "blocked");
  }
});

test("the independent oracle rejects a false tool, effect, resource, or callback claim", () => {
  for (const index of [1, 2, 4]) {
    const falsePermission = structuredClone(report);
    falsePermission.rows[index].receipt.policy_decision = "allow";
    assert.notEqual(verify(falsePermission).status, 0);
  }
  const missingCallback = structuredClone(report);
  missingCallback.rows[0].callback_count = 0;
  assert.notEqual(verify(missingCallback).status, 0);
  const changedDigest = structuredClone(report);
  changedDigest.rows[0].receipt.proposal_sha256 = "0".repeat(64);
  assert.notEqual(verify(changedDigest).status, 0);
});
