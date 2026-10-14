import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { axes, buildDispatchMatrix } from "../pilots/action-boundary/dispatch-matrix.mjs";

const report = JSON.parse(readFileSync(new URL("../docs/action-dispatch-matrix.json", import.meta.url), "utf8"));
const oracle = fileURLToPath(new URL("../pilots/action-boundary/verify_dispatch_matrix.py", import.meta.url));
const verify = value => spawnSync("python3", [oracle, "-"], {
  input: JSON.stringify(value), encoding: "utf8"
});

test("the 192 checked-in vectors are current and match the separate Python state oracle", async () => {
  assert.deepEqual(report, await buildDispatchMatrix());
  assert.equal(report.rows.length, Object.values(axes).reduce((total, items) => total * items.length, 1));
  const result = verify(report);
  assert.equal(result.status, 0, result.stderr);
  assert.equal(JSON.parse(result.stdout).vectors_verified, 192);
});

test("the oracle detects a false dispatch, missing callback, changed binding, and inflated claim", () => {
  const first = report.rows.findIndex(row => row.receipt.execution_status === "blocked");
  const invoked = report.rows.findIndex(row => row.callback_count === 1);
  const altered = () => structuredClone(report);
  const falseDispatch = altered();
  falseDispatch.rows[first].receipt.execution_status = "dispatched";
  assert.notEqual(verify(falseDispatch).status, 0);
  const missingCallback = altered();
  missingCallback.rows[invoked].callback_count = 0;
  assert.notEqual(verify(missingCallback).status, 0);
  const changedDigest = altered();
  changedDigest.rows[invoked].receipt.proposal_sha256 = "0".repeat(64);
  assert.notEqual(verify(changedDigest).status, 0);
  const inflatedClaim = altered();
  inflatedClaim.limits = "Formal proof of production safety";
  assert.notEqual(verify(inflatedClaim).status, 0);
});
