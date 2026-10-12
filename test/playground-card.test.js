import assert from "node:assert/strict";
import test from "node:test";
import { buildComparisonCard } from "../docs/playground-card.js";

const gate = (identifier, allowed, label) => ({
  identifier, matched: true,
  declaration: { label, purpose: "Explain & compare <options>", attention_cost: 5, restoration_value: allowed ? 5 : 1 },
  compiler: { render_allowed: allowed }, browser: { effective_rendered: allowed }
});
const record = {
  format: "aml-playground-local-run/v1", page: "https://example.org/playground.html",
  source_sha256: "a".repeat(64), gates: [gate("urgentOffer", false, "Buy <now>"), gate("clearDetails", true, "Read the terms")]
};

test("comparison card shows both observed outcomes and keeps untrusted text inert", () => {
  const svg = buildComparisonCard(record);
  assert.match(svg, /viewBox="0 0 1200 630"/);
  assert.match(svg, /SUPPRESS/);
  assert.match(svg, /ALLOW/);
  assert.match(svg, /BROWSER: WITHHELD/);
  assert.match(svg, /BROWSER: VISIBLE/);
  assert.match(svg, /Buy &lt;now&gt;/);
  assert.match(svg, /Explain &amp; compare &lt;options&gt;/);
  assert.doesNotMatch(svg, /Buy <now>|<options>/);
  assert.match(svg, /unsigned browser self-check/);
});

test("comparison card refuses an unmatched or single-gate record", () => {
  assert.throws(() => buildComparisonCard({ ...record, gates: [record.gates[0]] }), /matched two-gate/);
  const tampered = { ...record.gates[0], browser: { effective_rendered: true } };
  assert.throws(() => buildComparisonCard({ ...record, gates: [tampered, record.gates[1]] }), /matched two-gate/);
});
