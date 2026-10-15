import test from "node:test";
import assert from "node:assert/strict";
import { parseJsonWithoutDuplicateKeys } from "../runtime/strictJson.js";

test("rejects duplicate names in nested signed response objects, including escaped aliases", () => {
  for (const wire of [
    '{"receipt":{"protocol":"forged","protocol":"signed"}}',
    String.raw`{"effective_allowed":false,"effective_\u0061llowed":true}`,
    '{"items":[{"a":1},{"a":2,"a":3}]}',
    '{"__proto__":0,"__proto__":1}'
  ]) {
    assert.throws(() => parseJsonWithoutDuplicateKeys(wire), { code: "AML_DUPLICATE_JSON_KEY" });
  }
});

test("accepts repeated names in separate objects and punctuation inside string values", () => {
  const wire = JSON.stringify({ array: [{ name: "a" }, { name: "b" }],
    text: 'quote: \\" , { "name": [ ]', nested: { name: "c" } });
  assert.deepEqual(parseJsonWithoutDuplicateKeys(wire), JSON.parse(wire));
  assert.throws(() => parseJsonWithoutDuplicateKeys('{"a":1,,"b":2}'), SyntaxError);
});
