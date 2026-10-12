import assert from "node:assert/strict";
import test from "node:test";
import { MAX_SHARED_SOURCE, parsePlaygroundShare, playgroundShareUrl } from "../docs/playground-core.js";

const page = "https://aruintelligence.github.io/aml-core/playground.html";

test("a Unicode program survives a source-link round trip without server query data", () => {
  const source = 'transmission "hello" {\n  engram greeting {\n    value: "ĀML ✓ é 中文"\n    purpose: "Explain without urgency"\n    attention_cost: 2\n    restoration_value: 4\n  }\n}';
  const url = playgroundShareUrl(source, page + "?ignored=1#editor");
  assert.equal(new URL(url).search, "");
  assert.equal(parsePlaygroundShare(url), source);
  assert.equal(parsePlaygroundShare(page), null);
  assert.equal(parsePlaygroundShare(page + "#editor"), null);
  assert.equal(parsePlaygroundShare(page + "?example=compare#live-stage"), null);
});

test("malformed or oversized fragments never become program source", () => {
  for (const hash of ["v=2&source=x", "v=1&source=x&source=y", "v=1&source=x&extra=y", "v=1&source=%20%20"])
    assert.throws(() => parsePlaygroundShare(page + "#" + hash), RangeError);
  assert.throws(() => playgroundShareUrl("x".repeat(MAX_SHARED_SOURCE + 1), page), RangeError);
  assert.throws(() => playgroundShareUrl("", page), RangeError);
  assert.throws(() => parsePlaygroundShare(page + "#" + "x".repeat(12001)), RangeError);
});
