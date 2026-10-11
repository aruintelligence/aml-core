import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { planAction } from "./boundary.mjs";

const vectors = JSON.parse(readFileSync(new URL("./vectors.json", import.meta.url), "utf8"));

test("published vectors match the JavaScript reference", () => {
  assert.equal(vectors.protocol, "aml-action-vectors/1");
  for (const row of vectors.cases) {
    const plan = planAction(row.proposal, vectors.policy);
    assert.deepEqual([plan.proposal_sha256, plan.decision, plan.reason],
      [row.proposal_sha256, row.decision, row.reason], row.name);
  }
  assert.equal(vectors.cases[0].proposal_sha256, vectors.cases[1].proposal_sha256);
  assert.notEqual(vectors.cases[0].proposal_sha256, vectors.cases[2].proposal_sha256);
  assert.notEqual(vectors.cases[0].proposal_sha256, vectors.cases[3].proposal_sha256);
});
