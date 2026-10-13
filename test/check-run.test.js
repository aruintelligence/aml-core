import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import { checkLocalRun } from "../docs/check-run-core.js";
import { compileSourceBrowser } from "../docs/aml-browser.js";
import { comparisonSample } from "../docs/playground-core.js";
import { createLocalRunRecord } from "../docs/playground-record.js";

const source = comparisonSample();
const decisions = compileSourceBrowser(source).renderDecisions;
const entries = decisions.map((decision, index) => {
  const allowed = decision.render_allowed;
  return {
    index,
    declaration: {
      purpose: decision.purpose,
      label: index ? "Review the full terms" : "Buy before the timer expires",
      attention: decision.attention_cost,
      restoration: decision.restoration_value
    },
    detail: {
      ok: true, purpose: decision.purpose, attention_cost: decision.attention_cost,
      restoration_value: decision.restoration_value, deployment_mode: "enforce",
      failure_mode: "closed", render_allowed: allowed, effective_rendered: allowed
    },
    hidden: !allowed, observedAt: "2026-10-12T20:00:00.000Z"
  };
});
const record = await createLocalRunRecord({
  source, decisions, entries, pageUrl: "https://aruintelligence.github.io/aml-core/playground.html",
  generatedAt: "2026-10-12T20:01:00.000Z"
});

test("the published example distinguishes one source byte from one altered saved outcome", async () => {
  const example = JSON.parse(readFileSync(new URL("../docs/example-local-run.json", import.meta.url), "utf8"));
  const original = await checkLocalRun(JSON.stringify(example));
  assert.equal(original.consistent, true);
  assert.deepEqual(original.gates.map(gate => gate.recorded), ["withheld", "visible"]);
  const sourceChanged = await checkLocalRun(JSON.stringify({ ...example, source: example.source + "\n" }));
  assert.deepEqual(sourceChanged.checks.map(item => item.pass), [false, true, true]);
  const decisionsWithoutTime = text => compileSourceBrowser(text).renderDecisions.map(({ timestamp, ...decision }) => decision);
  assert.deepEqual(decisionsWithoutTime(example.source + "\n"), decisionsWithoutTime(example.source));
  assert.equal(new TextEncoder().encode(example.source + "\n").length - new TextEncoder().encode(example.source).length, 1);
  example.gates[0].browser.effective_rendered = true;
  const changed = await checkLocalRun(JSON.stringify(example));
  assert.deepEqual(changed.checks.map(item => item.pass), [true, true, false]);
  assert.equal(changed.gates[0].pass, false);
});

test("checker replays a matched local run and labels its limited conclusion", async () => {
  const result = await checkLocalRun(JSON.stringify(record));
  assert.equal(result.consistent, true);
  assert.deepEqual(result.checks.map(item => item.pass), [true, true, true]);
  assert.deepEqual(result.gates.map(item => item.recorded), ["withheld", "visible"]);
  assert.equal(result.source_sha256, record.source_sha256);
});

test("checker catches source and saved browser tampering separately", async () => {
  const sourceChanged = await checkLocalRun(JSON.stringify({ ...record, source: source + " " }));
  assert.equal(sourceChanged.consistent, false);
  assert.equal(sourceChanged.checks[0].pass, false);
  const forgedGate = { ...record.gates[0], browser: { ...record.gates[0].browser, effective_rendered: true } };
  const result = await checkLocalRun(JSON.stringify({ ...record, gates: [forgedGate, record.gates[1]] }));
  assert.equal(result.checks[0].pass, true);
  assert.equal(result.checks[2].pass, false);
  assert.equal(result.gates[0].pass, false);
});

test("checker rejects invalid JSON, shape, and duplicate gate indices", async () => {
  await assert.rejects(checkLocalRun("{"), /valid JSON/);
  await assert.rejects(checkLocalRun(JSON.stringify({ ...record, page: "../relative" })), /supported local run/);
  const duplicate = await checkLocalRun(JSON.stringify({ ...record, gates: [record.gates[0], record.gates[0]] }));
  assert.equal(duplicate.consistent, false);
  assert.equal(duplicate.gates[1].pass, false);
});
