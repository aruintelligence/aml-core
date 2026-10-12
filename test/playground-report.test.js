import assert from "node:assert/strict";
import test from "node:test";
import { buildComparisonReport } from "../docs/playground-report.js";

const gate = (identifier, allowed, label) => ({
  identifier, matched: true,
  declaration: { label, purpose: "Explain the offer", attention_cost: 5, restoration_value: allowed ? 5 : 1 },
  compiler: { render_allowed: allowed }, browser: { effective_rendered: allowed }
});
const source = 'transmission "</pre><script>alert(1)</script>" {}';
const record = {
  format: "aml-playground-local-run/v1", generated_at: "2026-10-12T20:01:00.000Z",
  page: "https://example.org/playground.html", source_sha256: "a".repeat(64), source,
  gates: [gate("urgentOffer", false, "Buy <now>"), gate("clearDetails", true, "Read the terms")]
};

test("offline report includes the matched card, exact source, rule and full record without executing source text", () => {
  const html = buildComparisonReport(record);
  assert.match(html, /Content-Security-Policy/);
  assert.match(html, /<svg[^>]*viewBox="0 0 1200 630"/);
  assert.match(html, /1 &lt; 5/);
  assert.match(html, /5 ≥ 5/);
  assert.match(html, /Compiler: <b>suppress<\/b> · Browser: <b>withheld<\/b>/);
  assert.match(html, /Compiler: <b>allow<\/b> · Browser: <b>visible<\/b>/);
  assert.match(html, /&lt;\/pre&gt;&lt;script&gt;alert\(1\)&lt;\/script&gt;/);
  assert.doesNotMatch(html, /<script>/);
  assert.match(html, /source_sha256/);
  assert.match(html, /#v=1&amp;source=/);
  assert.match(html, /href="https:\/\/example.org\/check-run.html"/);
});

test("oversized source stays inspectable offline without a truncated replay URL", () => {
  const html = buildComparisonReport({ ...record, source: "x".repeat(2401) });
  assert.match(html, /Source is too long for a replay link/);
  assert.doesNotMatch(html, /href="[^"]*#v=1/);
  assert.throws(() => buildComparisonReport({ ...record, gates: [record.gates[0]] }), /matched two-gate/);
});
