import test from "node:test";
import assert from "node:assert/strict";

import { compileSource, executeAccountableIntent, generateAMLFromIntent,
  replayExecutionReceipt, verifyExecutionReceipt } from "../index.js";
import { compileSourceBrowser } from "../docs/aml-browser.js";

const timestamp = "2030-01-01T00:00:00.000Z";

test("quoted identifiers and content stay inside one node and replay exactly", () => {
  const value = 'Say "yes" } engram "forged" {\nPath: C:\\Users\\Ada\n<ok>';
  const intent = { transmission: 'order "42"\nreview', nodes: [
    { type: "engram", identifier: 'card "A"\\side', properties: {
      value, purpose: 'Explain "the choice"\nwith care',
      attention_cost: 1, restoration_value: 8
    } }
  ] };
  const source = generateAMLFromIntent(intent);
  const compiled = compileSource(source, { timestamp });
  const browser = compileSourceBrowser(source);

  assert.equal(compiled.amt.root[0].identifier, intent.transmission);
  assert.equal(compiled.amt.root[0].children.find(node => node.type === "EngramNode")
    .identifier, intent.nodes[0].identifier);
  assert.equal(compiled.amt.root[0].children.find(node => node.type === "EngramNode")
    .properties.value, value);
  assert.equal(compiled.renderDecisions.length, 1, "quoted text cannot introduce a forged node");
  assert.equal(compiled.renderDecisions[0].purpose, intent.nodes[0].properties.purpose);
  assert.deepEqual(browser.ast, compiled.ast);
  assert.deepEqual(browser.amt, compiled.amt);
  assert.match(compiled.html, /Say &quot;yes&quot; \} engram &quot;forged&quot;/);
  assert.doesNotMatch(compiled.html, /<ok>/);

  const receipt = executeAccountableIntent(intent, { timestamp });
  assert.equal(receipt.selected_render.decisions.length, 1);
  assert.equal(receipt.selected_render.html, compiled.html);
  assert.equal(verifyExecutionReceipt(receipt).verified, true);
  assert.equal(replayExecutionReceipt(receipt).verified, true);
});

test("numeric scalars, zero, and exponent notation compile without changing values", () => {
  const intent = { transmission: "numbers", nodes: [
    { type: "engram", identifier: "zero", properties: {
      value: 0, attention_cost: 1e-7, restoration_value: 1
    } },
    { type: "mirror", identifier: "signed", properties: {
      speak: -2, reflect: 0
    } }
  ] };
  const source = generateAMLFromIntent(intent);
  const node = compileSource(source, { timestamp });
  const browser = compileSourceBrowser(source);
  assert.deepEqual(browser.ast, node.ast);
  assert.equal(node.amt.root[0].children[0].properties.attention_cost, 1e-7);
  assert.equal(node.amt.root[0].children[1].properties.speak, -2);
  assert.match(node.html, /<h2>0<\/h2>/);
  assert.match(node.html, /<p>-2<\/p>/);
  assert.match(node.html, /<p><em>0<\/em><\/p>/);

  const receipt = executeAccountableIntent(intent, { timestamp });
  assert.equal(receipt.selected_render.decisions[0].attention_cost, 1e-7);
  assert.equal(verifyExecutionReceipt(receipt).verified, true);
  assert.equal(replayExecutionReceipt(receipt).verified, true);
});

test("machine intents reject values that would silently change policy meaning", () => {
  for (const [key, value] of [
    ["attention_cost", NaN], ["attention_cost", Infinity],
    ["restoration_value", -1], ["attention_cost", "5"],
    ["cognitive_load", null], ["value", { secret: true }],
    ["value", ["a", "b"]], ["value", undefined]
  ]) {
    const intent = { nodes: [{ type: "engram", properties: { [key]: value } }] };
    assert.throws(() => generateAMLFromIntent(intent), /must be/,
      `${key}=${String(value)} must not become a different AML value`);
    assert.throws(() => executeAccountableIntent(intent, { timestamp }), /must be/);
  }
  assert.throws(() => generateAMLFromIntent({ transmission: 0, nodes: [] }),
    /intent.transmission must be a string/);
  assert.throws(() => generateAMLFromIntent({ nodes: [{ type: "engram", identifier: 0 }] }),
    /node.identifier must be a string/);
  assert.throws(() => generateAMLFromIntent({ nodes: null }), /intent.nodes must be an array/);
});

test("source-authored policy scores cannot bypass numeric validation", () => {
  for (const value of ['"5"', "NaN", "-1", "Infinity"]) {
    const source = `transmission "invalid" { engram "card" {
      value: "A card"
      attention_cost: ${value}
      restoration_value: 8
    } }`;
    assert.throws(() => compileSource(source), /property attention_cost must be a non-negative finite number/);
    assert.throws(() => compileSourceBrowser(source), /property attention_cost must be a non-negative finite number/);
  }
});

test("invalid escape sequences fail closed in Node and browser lexers", () => {
  const bad = String.raw`transmission "bad" { engram "card" { value: "bad\q" } }`;
  const badUnicode = String.raw`transmission "bad" { engram "card" { value: "bad\uZZZZ" } }`;
  for (const source of [bad, badUnicode]) {
    assert.throws(() => compileSource(source), /Invalid (string|unicode) escape/);
    assert.throws(() => compileSourceBrowser(source), /Invalid (string|unicode) escape/);
  }
});

test("explicit Unicode escapes and overflowing numbers have the same browser behavior", () => {
  const unicode = String.raw`transmission "unicode" { engram "card" { value: "\u0041 \uD83D\uDE00" } }`;
  const node = compileSource(unicode);
  const browser = compileSourceBrowser(unicode);
  assert.equal(node.amt.root[0].children[0].properties.value, "A 😀");
  assert.deepEqual(browser.ast, node.ast);
  const overflow = 'transmission "overflow" { engram "card" { attention_cost: 1e309 } }';
  assert.throws(() => compileSource(overflow), /Invalid number/);
  assert.throws(() => compileSourceBrowser(overflow), /Invalid number/);
});
