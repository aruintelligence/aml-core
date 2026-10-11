import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { webcrypto } from "node:crypto";
import { planAction } from "../pilots/action-boundary/boundary.mjs";
import { planPreview, rehearse } from "../docs/action-lab-core.js";

const vectors = JSON.parse(readFileSync(new URL("../pilots/action-boundary/vectors.json", import.meta.url), "utf8"));
const html = readFileSync(new URL("../docs/action-lab.html", import.meta.url), "utf8");
const ui = readFileSync(new URL("../docs/action-lab.js", import.meta.url), "utf8");

test("the browser lab reproduces all six published action digests and decisions", async () => {
  for (const row of vectors.cases) {
    const browser = await planPreview(row.proposal, vectors.policy, webcrypto.subtle);
    const node = planAction(row.proposal, vectors.policy);
    assert.deepEqual([browser.proposal_sha256, browser.decision, browser.reason],
      [row.proposal_sha256, row.decision, row.reason], row.name);
    assert.deepEqual([browser.proposal_sha256, browser.decision, browser.reason],
      [node.proposal_sha256, node.decision, node.reason], row.name);
  }
});

test("changing an approved proposal invalidates the simulated approval", async () => {
  const original = await planPreview(vectors.cases[0].proposal, vectors.policy, webcrypto.subtle);
  const changed = await planPreview(vectors.cases[3].proposal, vectors.policy, webcrypto.subtle);
  assert.equal(rehearse(original, original.proposal_sha256).outcome, "would_dispatch");
  assert.deepEqual(rehearse(changed, original.proposal_sha256),
    { outcome: "blocked", reason: "approval_missing_or_mismatched" });
  assert.equal(rehearse(original, original.proposal_sha256, true).outcome, "unknown");
  assert.equal(rehearse(await planPreview(vectors.cases[2].proposal, vectors.policy, webcrypto.subtle),
    original.proposal_sha256).outcome, "blocked");
});

test("malformed and ambiguous host policies deny in the browser mirror", async () => {
  const proposal = vectors.cases[0].proposal;
  const ambiguous = { ...vectors.policy, rules: [...vectors.policy.rules, vectors.policy.rules[0]] };
  assert.equal((await planPreview(proposal, ambiguous, webcrypto.subtle)).reason, "ambiguous_policy");
  assert.equal((await planPreview({ ...proposal, extra: true }, vectors.policy, webcrypto.subtle)).reason,
    "invalid_proposal");
  assert.equal((await planPreview(proposal, { rules: [] }, webcrypto.subtle)).reason, "invalid_policy");
});

test("the public page exposes its limitations and uses only local browser inputs", () => {
  assert.match(html, /Browser rehearsal only/);
  assert.match(html, /No tool runs, no message is sent/);
  assert.match(html, /Local browser inputs are not uploaded/);
  assert.match(html, /action-lab\.js/);
  assert.match(ui, /planPreview\(proposal, policy, crypto\.subtle\)/);
  assert.doesNotMatch(ui, /\bfetch\(|XMLHttpRequest|sendBeacon/);
});
