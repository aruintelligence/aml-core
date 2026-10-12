import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import { downloadablePage, integrationSnippet, normalizeIntegration } from "../docs/quickstart-core.js";

const example = {
  purpose: "Create urgency for a purchase", label: "Review details",
  attention: 5, restoration: 1, mode: "enforce"
};

test("download and snippet carry the same complete gate declaration", () => {
  const snippet = integrationSnippet(example);
  const page = downloadablePage(example);
  const gate = snippet.slice(snippet.indexOf("<aml-gate"));
  assert.ok(page.includes(gate));
  assert.match(gate, /attention-cost="5"[\s\S]*restoration-value="1"[\s\S]*mode="enforce"[\s\S]*failure-mode="closed"/);
  assert.ok(page.indexOf("addEventListener('aml-decision'") < page.indexOf('type="module" src='));
  assert.match(page, /result\.effective_rendered/);
  assert.match(integrationSnippet({ ...example, mode: "shadow" }), /mode="shadow"/);
});

test("user text remains text inside a downloadable HTML page", () => {
  const hostile = '" autofocus onfocus="alert(1)\n\n<script>alert(2)</script>&';
  const page = downloadablePage({ ...example, purpose: hostile, label: hostile });
  assert.ok(page.includes('&quot; autofocus onfocus=&quot;alert(1)'));
  assert.ok(page.includes('&lt;script&gt;alert(2)&lt;/script&gt;&amp;'));
  assert.ok(!page.includes('<script>alert(2)</script>'));
  assert.equal((page.match(/<aml-gate\b/g) || []).length, 1);
});

test("only bounded declarations produce copyable HTML", () => {
  assert.throws(() => normalizeIntegration({ ...example, purpose: " " }), RangeError);
  assert.throws(() => integrationSnippet({ ...example, attention: 11 }), RangeError);
  assert.throws(() => downloadablePage({ ...example, mode: "approve" }), RangeError);
  assert.deepEqual(normalizeIntegration({ ...example, restoration: "10" }).restoration, 10);
});

test("studio explicitly honors a suppressed custom element's hidden state", () => {
  const page = readFileSync(new URL("../docs/quickstart.html", import.meta.url), "utf8");
  assert.match(page, /\.preview aml-gate\[hidden\]\{display:none\}/);
  assert.match(page, /<script type="module" src="\.\/quickstart\.js"><\/script>/);
});
