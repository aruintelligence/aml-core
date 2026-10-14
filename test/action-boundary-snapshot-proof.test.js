import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { buildSnapshotProof } from "../pilots/action-boundary/snapshot-proof.mjs";

const report = JSON.parse(readFileSync(new URL("../docs/action-snapshot-proof.json", import.meta.url), "utf8"));
const oracle = fileURLToPath(new URL("../pilots/action-boundary/verify_snapshot_proof.py", import.meta.url));
const verify = value => spawnSync("python3", [oracle, "-"], {
  input: JSON.stringify(value), encoding: "utf8"
});

test("one canonical snapshot binds the receipt and callback in both approval modes", async () => {
  assert.deepEqual(await buildSnapshotProof(), report);
  const result = verify(report);
  assert.equal(result.status, 0, result.stderr);
  assert.equal(JSON.parse(result.stdout).cases_verified, 2);
  assert.deepEqual(report.rows.map(row => [row.mode, row.accessor_reads,
    row.callback_body, row.receipt_matches_callback]), [
    ["allow", 1, "First observed body", true],
    ["requires_approval", 1, "First observed body", true]
  ]);
});

test("the oracle rejects a split receipt, a second accessor read, and an inflated scope", () => {
  const split = structuredClone(report);
  split.rows[0].callback_sha256 = "0".repeat(64);
  split.rows[0].receipt_matches_callback = false;
  assert.notEqual(verify(split).status, 0);
  const doubleRead = structuredClone(report);
  doubleRead.rows[1].accessor_reads = 2;
  assert.notEqual(verify(doubleRead).status, 0);
  const inflated = structuredClone(report);
  inflated.limits = "Production safety proof";
  assert.notEqual(verify(inflated).status, 0);
});
