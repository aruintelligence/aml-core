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

  test(`${name} canonical JSON does not call input-controlled array methods`, () => {
    const array = ["original"];
    array.map = () => { throw new Error("attacker method ran"); };
    assert.equal(stringify({ recipients: array }), '{"recipients":["original"]}');
    // The old wire profile maps a hole to null; the browser receipt verifier
    // separately rejects that malformed live input before sealing.
    assert.equal(stringify({ recipients: [, "second"] }),
      '{"recipients":[null,"second"]}');
  });

  test(`${name} canonical JSON ignores inherited serialization hooks`, () => {
    const value = { action: { destination: "approved" }, arguments: ["first", { count: 2 }] };
    const expected = stringify(value);
    const objectHook = Object.getOwnPropertyDescriptor(Object.prototype, "toJSON");
    const arrayHook = Object.getOwnPropertyDescriptor(Array.prototype, "toJSON");
    try {
      Object.prototype.toJSON = () => ({ action: "substituted" });
      Array.prototype.toJSON = () => ["substituted"];
      assert.equal(stringify(value), expected);
    } finally {
      if (objectHook) Object.defineProperty(Object.prototype, "toJSON", objectHook);
      else delete Object.prototype.toJSON;
      if (arrayHook) Object.defineProperty(Array.prototype, "toJSON", arrayHook);
      else delete Array.prototype.toJSON;
    }
  });

  test(`${name} rejects a cycle but permits a repeated JSON subtree`, () => {
    const cyclic = { label: "cycle" };
    cyclic.self = cyclic;
    assert.throws(() => stringify(cyclic), /AML_CANONICAL_JSON_CYCLE/);
    const shared = { value: "same" };
    assert.equal(stringify({ a: shared, b: shared }),
      '{"a":{"value":"same"},"b":{"value":"same"}}');
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
