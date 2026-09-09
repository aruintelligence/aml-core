import test from "node:test";
import assert from "node:assert/strict";

import { canonicalJSONStringify } from "../protocol/canonicalJson.js";
import { canonicalJSONStringifyBrowser } from "../docs/aml-browser-integrity.js";

const canonicalizers = [
  ["node", canonicalJSONStringify],
  ["browser", canonicalJSONStringifyBrowser]
];

for (const [name, stringify] of canonicalizers) {
  test(`${name} canonical JSON preserves sorted ordinary JSON`, () => {
    assert.equal(
      stringify({ z: 1, a: { y: 2, x: [true, null, "ok"] } }),
      '{"a":{"x":[true,null,"ok"],"y":2},"z":1}'
    );
  });

  test(`${name} canonical JSON rejects non-finite numeric collisions`, () => {
    assert.throws(() => stringify({ value: Number.NaN }), /AML_CANONICAL_JSON_NON_FINITE_NUMBER/);
    assert.throws(() => stringify({ value: Infinity }), /AML_CANONICAL_JSON_NON_FINITE_NUMBER/);
    assert.throws(() => stringify({ value: -Infinity }), /AML_CANONICAL_JSON_NON_FINITE_NUMBER/);
    assert.equal(stringify({ value: null }), '{"value":null}');
  });

  test(`${name} canonical JSON rejects disappearing undefined values`, () => {
    assert.throws(() => stringify({ authorization: undefined }), /AML_CANONICAL_JSON_UNSUPPORTED_VALUE/);
    assert.throws(() => stringify([undefined]), /AML_CANONICAL_JSON_UNSUPPORTED_VALUE/);
    assert.equal(stringify({}), '{}');
    assert.equal(stringify([null]), '[null]');
  });

  test(`${name} canonical JSON rejects non-plain objects instead of collapsing them`, () => {
    assert.throws(() => stringify({ when: new Date("2030-01-01T00:00:00.000Z") }), /AML_CANONICAL_JSON_NON_PLAIN_OBJECT/);
  });

  test(`${name} canonical JSON rejects unsupported executable or non-JSON primitives`, () => {
    assert.throws(() => stringify({ fn: () => true }), /AML_CANONICAL_JSON_UNSUPPORTED_VALUE/);
    assert.throws(() => stringify({ id: 1n }), /AML_CANONICAL_JSON_UNSUPPORTED_VALUE/);
    assert.throws(() => stringify(Symbol("x")), /AML_CANONICAL_JSON_UNSUPPORTED_VALUE/);
  });
}

test("node and browser canonical JSON remain byte-identical for JSON values", () => {
  const value = {
    nested: { b: 2, a: 1 },
    array: [3, { z: false, a: "first" }],
    zero: 0
  };
  assert.equal(canonicalJSONStringify(value), canonicalJSONStringifyBrowser(value));
});
