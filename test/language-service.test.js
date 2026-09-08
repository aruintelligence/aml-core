import test from "node:test";
import assert from "node:assert/strict";

import { getCompletionItems, getHoverInfo, getLanguageCatalog } from "../index.js";

test("AML language service returns block and property completions", () => {
  const all = getCompletionItems();
  assert.ok(all.some(item => item.label === "transmission" && item.kind === "block"));
  assert.ok(all.some(item => item.label === "attention_cost" && item.kind === "property"));
});

test("AML completion filtering is prefix-aware", () => {
  const items = getCompletionItems("rest");
  assert.ok(items.length > 0);
  assert.ok(items.every(item => item.label.startsWith("rest")));
  assert.ok(items.some(item => item.label === "restoration_value"));
});

test("AML hover information documents known symbols", () => {
  const hover = getHoverInfo("purpose");
  assert.equal(hover.kind, "property");
  assert.match(hover.documentation, /reason/i);
  assert.equal(getHoverInfo("not_a_real_aml_symbol"), null);
});

test("AML language catalog is machine readable", () => {
  const catalog = getLanguageCatalog();
  assert.equal(catalog.version, "1.1.0");
  assert.ok(catalog.blocks.engram);
  assert.ok(catalog.operators.includes(">="));
});
