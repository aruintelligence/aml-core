import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import test from "node:test";
import { inspectPolicyTuple, tupleIndex, tupleSelection, tupleUrl } from "../docs/policy-tuple.js";

const report = JSON.parse(readFileSync(new URL("../docs/action-policy-tuple.json", import.meta.url), "utf8"));
const page = readFileSync(new URL("../docs/policy-tuple.html", import.meta.url), "utf8");
const script = readFileSync(new URL("../docs/policy-tuple.js", import.meta.url));

test("the eight-cell viewer follows the checked-in tuple ordering and direct links", () => {
  assert.deepEqual(inspectPolicyTuple(report), { dispatched: 1, blocked: 7 });
  for (const [index, row] of report.rows.entries()) {
    assert.equal(tupleIndex(row.match.tool, row.match.effect, row.match.resource), index);
    const url = tupleUrl("https://example.test/policy-tuple.html", index);
    assert.equal(tupleSelection(new URL(url).search), index);
    assert.equal(new URL(url).hash, "#inspection");
  }
  assert.equal(tupleSelection("?case=8"), 0);
  assert.throws(() => tupleUrl("https://example.test", 8), RangeError);
});

test("the page ties its presentation to the checked-in report and current script", () => {
  const falseReceipt = structuredClone(report);
  falseReceipt.rows[2].receipt.execution_status = "dispatched";
  assert.throws(() => inspectPolicyTuple(falseReceipt), /case 2/);
  for (const required of ["action-policy-tuple.json", "action-dispatch-mutants.json",
    "binding-rows", "tuple-grid", "no human approval", "formal proof of production safety",
    "does not independently verify provenance"]) {
    assert.ok(page.toLowerCase().includes(required.toLowerCase()), required);
  }
  const version = createHash("sha256").update(script).digest("hex").slice(0, 12);
  assert.ok(page.includes(`src="policy-tuple.js?v=${version}"`));
});
