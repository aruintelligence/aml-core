import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import { inspectMatrix, MATRIX_AXES, matrixIndex, matrixInsights, matrixSelection, matrixUrl,
  visibleMatrixIndices } from "../docs/dispatch-matrix.js";

const report = JSON.parse(readFileSync(new URL("../docs/action-dispatch-matrix.json", import.meta.url), "utf8"));
const page = readFileSync(new URL("../docs/dispatch-matrix.html", import.meta.url), "utf8");

test("the atlas indexes every vector and filters the actual checked-in outcomes", () => {
  assert.deepEqual(inspectMatrix(report), { blocked: 140, dispatched: 26, unknown: 26 });
  for (const [index, row] of report.rows.entries()) {
    assert.equal(matrixIndex(row.policy, row.approval, row.claim, row.callback), index);
  }
  assert.equal(visibleMatrixIndices(report).length, 192);
  assert.equal(visibleMatrixIndices(report, "deny", "blocked").length, 48);
  assert.equal(visibleMatrixIndices(report, "deny", "unknown").length, 0);
  assert.equal(visibleMatrixIndices(report, "requires_approval", "unknown").length, 2);
  assert.throws(() => visibleMatrixIndices(report, "unknown_policy"), RangeError);
});

test("the highlighted cases retain the side effects hidden by a one-word status", () => {
  assert.deepEqual(matrixInsights(report), {
    spent_and_blocked: 8, unknown_after_write: 26, frozen_after_mutation: 2
  });
  const spent = report.rows[100];
  assert.deepEqual([spent.receipt.execution_status, spent.claims_consumed, spent.callback_count],
    ["blocked", 1, 0]);
  const uncertain = report.rows[49];
  assert.deepEqual([uncertain.receipt.execution_status, uncertain.callback_count, uncertain.fixture_writes],
    ["unknown", 1, 1]);
  const frozen = report.rows[136];
  assert.deepEqual([frozen.caller_target_after, frozen.callback_target],
    ["other@example.test", "team@example.test"]);
  const url = matrixUrl("https://example.test/dispatch-matrix.html?policy=allow", 49, report);
  assert.equal(new URL(url).hash, "#case");
  assert.equal(matrixSelection(new URL(url).search, visibleMatrixIndices(report)), 49);
  assert.equal(matrixSelection("?vector=192", visibleMatrixIndices(report, "allow")), 48);
  assert.throws(() => matrixUrl(url, 192, report), RangeError);
});

test("the viewer rejects malformed axes or totals and marks its evidence boundary", () => {
  const changedAxes = structuredClone(report);
  changedAxes.axes.callback.reverse();
  assert.throws(() => inspectMatrix(changedAxes), /format/);
  const falseOutcome = structuredClone(report);
  falseOutcome.rows[0].receipt.execution_status = "dispatched";
  assert.throws(() => inspectMatrix(falseOutcome), /totals/);
  assert.deepEqual(Object.keys(MATRIX_AXES), ["policy", "approval", "claim", "callback"]);
  for (const required of ["data-preset=\"100\"", "data-preset=\"49\"", "data-preset=\"136\"",
    "No human approval", "no human approval", "formal proof of production safety",
    "does not independently verify its provenance", "dispatch-matrix.js"]) {
    assert.match(page.toLowerCase(), new RegExp(required.toLowerCase()));
  }
});
