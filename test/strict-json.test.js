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

test("optional portable parser checks numeric tokens outside JSON strings", () => {
  const options = { integerNumbersOnly: true };
  assert.deepEqual(parseJsonWithoutDuplicateKeys('{"text":"1.0 and 2e3", "count":1}', options),
    { text: '1.0 and 2e3', count: 1 });
  for (const token of ['1.0', '1e0', '0.5', '9007199254740992']) {
    assert.throws(() => parseJsonWithoutDuplicateKeys(`{"count":${token}}`, options),
      { code: 'AML_NON_PORTABLE_JSON_NUMBER' });
  }
  assert.deepEqual(parseJsonWithoutDuplicateKeys('{"count":1.0}'), { count: 1 });
});
