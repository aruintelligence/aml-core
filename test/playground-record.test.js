import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test from "node:test";
import { compileSourceBrowser } from "../docs/aml-browser.js";
import { createLocalRunRecord } from "../docs/playground-record.js";

const source = `transmission "sample" {
  engram urgent { value: "Buy now" purpose: "Prompt a purchase" attention_cost: 5 restoration_value: 1 }
  engram clear { value: "Read terms" purpose: "Explain the offer" attention_cost: 5 restoration_value: 5 }
}`;
const decisions = compileSourceBrowser(source).renderDecisions;
const entry = (index, label) => {
  const decision = decisions[index];
  const allowed = decision.render_allowed;
  return {
    index,
    declaration: { purpose: decision.purpose, label, attention: 5, restoration: decision.restoration_value },
    detail: {
      ok: true, purpose: decision.purpose, attention_cost: 5,
      restoration_value: decision.restoration_value, deployment_mode: "enforce",
      failure_mode: "closed", render_allowed: allowed, effective_rendered: allowed
    },
    hidden: !allowed,
    observedAt: "2026-10-12T20:00:00.000Z"
  };
};

test("local run record binds the exact source to distinct matched browser events", async () => {
  const record = await createLocalRunRecord({
    source, decisions, entries: [entry(0, "Buy now"), entry(1, "Read terms")],
    pageUrl: "https://example.org/playground.html?example=compare#live-stage",
    generatedAt: "2026-10-12T20:01:00.000Z"
  });
  assert.equal(record.source_sha256, createHash("sha256").update(source).digest("hex"));
  assert.equal(record.page, "https://example.org/playground.html");
  assert.deepEqual(record.gates.map(gate => gate.browser.effective_rendered), [false, true]);
  assert.equal(record.previewed_gate_count, 2);
  assert.equal(record.gates[0].declaration.label, "Buy now");
  assert.match(record.scope, /Unsigned/);
});

test("local run record rejects mismatches and repeated decisions", async () => {
  const first = entry(0, "Buy now");
  await assert.rejects(createLocalRunRecord({
    source, decisions, entries: [{ ...first, detail: { ...first.detail, effective_rendered: true } }],
    pageUrl: "https://example.org/playground.html"
  }), /did not match/);
  await assert.rejects(createLocalRunRecord({
    source, decisions, entries: [first, first], pageUrl: "https://example.org/playground.html"
  }), /did not match/);
});
