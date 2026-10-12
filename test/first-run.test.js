import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { webcrypto } from "node:crypto";
import test from "node:test";
import { firstRunAction, firstRunPolicy, firstRunProposal, renderDecision } from "../docs/first-run.js";

const vectors = JSON.parse(readFileSync(new URL("../pilots/action-boundary/vectors.json", import.meta.url), "utf8"));

test("first-run agent scenarios match the published proposal, policy, decision, and digest", async () => {
  assert.deepEqual(firstRunPolicy.rules[0], vectors.policy.rules[0]);
  for (const [recipient, name] of [["team", "approved_route"], ["outside", "changed_destination"]]) {
    const expected = vectors.cases.find(item => item.name === name);
    assert.deepEqual(firstRunProposal(recipient), expected.proposal);
    const observed = await firstRunAction(recipient, webcrypto.subtle);
    assert.equal(observed.decision, expected.decision);
    assert.equal(observed.reason, expected.reason);
    assert.equal(observed.proposal_sha256, expected.proposal_sha256);
    assert.equal(observed.project_vector_matches, true);
    assert.equal(observed.tool_callbacks, 0);
  }
});

test("declared render values change at the exact threshold", () => {
  assert.equal(renderDecision(5, 1).decision, "suppress");
  assert.equal(renderDecision(5, 5).decision, "allow");
  assert.throws(() => renderDecision(11, 1), RangeError);
  assert.throws(() => firstRunProposal("another recipient"), RangeError);
});
