import assert from "node:assert/strict";
import test from "node:test";
import { compileSourceBrowser } from "../docs/aml-browser.js";
import { MAX_SHARED_SOURCE, comparisonRestoration, comparisonSample, parsePlaygroundShare, playgroundShareUrl } from "../docs/playground-core.js";

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

test("the comparison dial owns only its exact sample and stays inside its range", () => {
  for (const restoration of [0, 1, 4, 5, 10]) {
    const source = comparisonSample(restoration);
    assert.equal(comparisonRestoration(source), restoration);
    assert.match(source, new RegExp(`restoration_value: ${restoration}\\n  }\\n  engram clearDetails`));
    assert.match(source, /value: "Buy before the timer expires"/);
  }
  assert.equal(comparisonRestoration(comparisonSample().replace("Buy before", "Act before")), null);
  assert.equal(comparisonRestoration(comparisonSample() + "\n"), null);
  assert.equal(comparisonRestoration(null), null);
  assert.throws(() => comparisonSample(11), RangeError);
  assert.throws(() => comparisonSample(-1), RangeError);
  assert.throws(() => comparisonSample(1.5), RangeError);
});

test("the dial crosses the browser compiler boundary at the declared threshold", () => {
  for (const restoration of [1, 4, 5, 10]) {
    const [offer, details] = compileSourceBrowser(comparisonSample(restoration)).renderDecisions;
    assert.equal(offer.identifier, "urgentOffer");
    assert.equal(offer.restoration_value, restoration);
    assert.equal(offer.render_allowed, restoration >= 5);
    assert.equal(details.identifier, "clearDetails");
    assert.equal(details.render_allowed, true);
  }
});
