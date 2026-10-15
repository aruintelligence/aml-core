import test from "node:test";
import assert from "node:assert/strict";

import { compileSource, policyFromProfile, simulatePolicies } from "../index.js";
import { compileSourceBrowser } from "../docs/aml-browser.js";

const timestamp = "2030-01-01T00:00:00.000Z";
const options = { timestamp, policy: policyFromProfile("calm_default"),
  context: { consent_granted: false } };

test("conflicting consent declarations cannot replace a denied policy input", () => {
  for (const declarations of [
    "consent_required: required consent_required: false",
    "consent_required: false consent_required: required",
    "consent_required: required consent_required: required"
  ]) {
    const source = `transmission "ambiguous" { engram "panel" {
      value: "PRIVATE_6381"
      ${declarations}
      attention_cost: 1 restoration_value: 8
    } }`;
    assert.throws(() => compileSource(source, options),
      /Duplicate ĀML property "consent_required" in engram block/);
    assert.throws(() => compileSourceBrowser(source),
      /Duplicate ĀML property "consent_required" in engram block/);
    assert.throws(() => simulatePolicies(source, ["consent_guard_v1"], options),
      /Duplicate ĀML property "consent_required" in engram block/);
  }
});

test("duplicate content and purpose declarations fail even when values match", () => {
  for (const duplicated of [
    'value: "first" value: "second"',
    'purpose: "same" purpose: "same"',
    "attention_cost: 1 attention_cost: 1"
  ]) {
    const source = `transmission "ambiguous" { engram "panel" { ${duplicated} } }`;
    assert.throws(() => compileSource(source), /Duplicate ĀML property/);
    assert.throws(() => compileSourceBrowser(source), /Duplicate ĀML property/);
  }
});

test("the same property in independent sibling blocks remains valid", () => {
  const source = `transmission "siblings" {
    engram "private" { value: "PRIVATE_7293" consent_required: required }
    engram "public" { value: "PUBLIC_8217" consent_required: false }
  }`;
  const result = compileSource(source, options);
  const browser = compileSourceBrowser(source);
  assert.deepEqual(result.renderDecisions.map(d => d.render_allowed), [false, true]);
  assert.doesNotMatch(result.html, /PRIVATE_7293/);
  assert.match(result.html, /PUBLIC_8217/);
  assert.deepEqual(browser.amt, result.amt);
});

test("prototype-like property names remain own data without changing the object prototype", () => {
  const source = `transmission "keys" {
    engram "panel" { __proto__: "declared" constructor: "plain" value: "SAFE_3145" }
  }`;
  const node = compileSource(source);
  const browser = compileSourceBrowser(source);
  const properties = node.amt.root[0].children[0].properties;
  assert.equal(Object.hasOwn(properties, "__proto__"), true);
  assert.equal(properties.__proto__, "declared");
  assert.equal(properties.constructor, "plain");
  assert.equal(Object.getPrototypeOf(properties), Object.prototype);
  assert.deepEqual(browser.amt, node.amt);
  assert.match(node.html, /SAFE_3145/);
});
