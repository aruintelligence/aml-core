import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { webcrypto } from "node:crypto";
import { makeStudioBundle, verifyStudioBundle } from "../pilots/action-boundary/studio-bundle.mjs";
import { planPreview } from "../docs/action-lab-core.js";

const vectors = JSON.parse(readFileSync(new URL("../pilots/action-boundary/vectors.json", import.meta.url), "utf8"));
const example = JSON.parse(readFileSync(new URL("../examples/action-studio/changed-destination.json", import.meta.url), "utf8"));
const copy = value => JSON.parse(JSON.stringify(value));

test("published example rechecks independently of the browser mirror", async () => {
  assert.deepEqual(verifyStudioBundle(example).failures, []);
  assert.equal(verifyStudioBundle(example).consistent, true);
  assert.equal(example.plan.decision, "deny");
  assert.equal(example.plan.reason, "no_exact_rule");
  for (const row of vectors.cases) {
    const reference = makeStudioBundle(row.proposal, vectors.policy);
    const browser = await planPreview(row.proposal, vectors.policy, webcrypto.subtle);
    assert.deepEqual(reference.plan, { protocol: browser.protocol, proposal_sha256: browser.proposal_sha256,
      decision: browser.decision, reason: browser.reason }, row.name);
    assert.equal(reference.canonical_proposal_json, browser.canonical_json, row.name);
  }
});

test("same route with different body retains the rule but changes the digest", () => {
  const original = makeStudioBundle(vectors.cases[0].proposal, vectors.policy);
  const changed = makeStudioBundle(vectors.cases[3].proposal, vectors.policy);
  assert.equal(original.plan.decision, "requires_approval");
  assert.equal(changed.plan.decision, "requires_approval");
  assert.notEqual(original.plan.proposal_sha256, changed.plan.proposal_sha256);
});

test("mismatched proposal, policy, plan, and canonical JSON are rejected", () => {
  const cases = [
    bundle => { bundle.proposal.resource = "team@example.test"; },
    bundle => { bundle.policy.rules.push({ tool: "send_message", effect: "send",
      resource: "outsider@example.test", requires_approval: false }); },
    bundle => { bundle.plan.decision = "allow"; },
    bundle => { bundle.canonical_proposal_json += " "; },
    bundle => { bundle.plan.extra = true; }
  ];
  for (const alter of cases) {
    const tampered = copy(example); alter(tampered);
    assert.equal(verifyStudioBundle(tampered).consistent, false);
    assert.ok(verifyStudioBundle(tampered).failures.length);
  }
});

test("malformed or ambiguous policy produces a consistent denied calculation", async () => {
  const proposal = vectors.cases[0].proposal;
  for (const policy of [{ protocol: "wrong", rules: [] },
    { ...vectors.policy, rules: [...vectors.policy.rules, vectors.policy.rules[0]] }]) {
    const bundle = makeStudioBundle(proposal, policy);
    const preview = await planPreview(proposal, policy, webcrypto.subtle);
    assert.equal(bundle.plan.decision, "deny");
    assert.equal(bundle.plan.proposal_sha256, null);
    assert.equal(bundle.canonical_proposal_json, null);
    assert.equal(bundle.plan.reason, preview.reason);
    assert.equal(verifyStudioBundle(bundle).consistent, true);
  }
  assert.equal(verifyStudioBundle({}).consistent, false);
});

test("public Studio labels its authority limits and does no network upload", () => {
  const html = readFileSync(new URL("../docs/action-boundary-studio.html", import.meta.url), "utf8");
  const ui = readFileSync(new URL("../docs/action-boundary-studio.js", import.meta.url), "utf8");
  assert.match(html, /it does not run a tool/);
  assert.match(html, /No network upload/);
  assert.match(html, /aria-live="polite"/);
  assert.match(ui, /planPreview\(input, rules, crypto\.subtle\)/);
  assert.doesNotMatch(ui, /\bfetch\(|XMLHttpRequest|sendBeacon/);
});
