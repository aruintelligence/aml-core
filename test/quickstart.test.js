import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import { downloadablePage, integrationSnippet, normalizeIntegration, parseSharedIntegration, shareableStudioUrl } from "../docs/quickstart-core.js";

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
  assert.match(page, /<script type="module" src="\.\/quickstart\.js\?v=unicode-share-2"><\/script>/);
});

test("scenario link restores the exact bounded declaration without a request query", () => {
  const custom = { ...example, purpose: "Explain A&B <carefully>", label: "See how ✓ works", restoration: 8, mode: "shadow" };
  const link = shareableStudioUrl(custom, "https://example.test/aml-core/quickstart.html?attention=3#studio");
  const url = new URL(link);
  assert.equal(url.search, "");
  assert.equal(url.pathname, "/aml-core/quickstart.html");
  assert.ok(url.hash.includes("purpose="));
  assert.deepEqual(parseSharedIntegration(link), normalizeIntegration(custom));
  assert.equal(parseSharedIntegration("https://example.test/aml-core/quickstart.html#studio"), null);
});

test("malformed, duplicate, and oversized share state cannot be applied", () => {
  const valid = shareableStudioUrl(example, "https://example.test/quickstart.html");
  assert.throws(() => parseSharedIntegration(valid + "&attention=0"), RangeError);
  assert.throws(() => parseSharedIntegration(valid.replace("v=1", "v=2")), RangeError);
  assert.throws(() => parseSharedIntegration(valid.replace("mode=enforce", "mode=approve")), RangeError);
  assert.throws(() => parseSharedIntegration(valid.replace("purpose=Create+urgency+for+a+purchase", "purpose=" + "x".repeat(121))), RangeError);
  assert.throws(() => parseSharedIntegration(valid + "&extra=" + "x".repeat(4100)), RangeError);
  const page = readFileSync(new URL("../docs/quickstart.html", import.meta.url), "utf8");
  assert.match(page, /id="share"/);
  assert.match(page, /id="share-url"/);
});

test("the longest accepted Unicode labels round-trip through a shared link", () => {
  const input = { ...example, purpose: "界".repeat(120), label: "界".repeat(120) };
  const link = shareableStudioUrl(input, "https://example.test/quickstart.html");
  assert.ok(new URL(link).hash.length > 1000);
  assert.deepEqual(parseSharedIntegration(link), input);
});
