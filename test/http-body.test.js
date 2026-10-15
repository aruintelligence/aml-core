import test from "node:test";
import assert from "node:assert/strict";
import { PassThrough } from "node:stream";
import { readJson } from "../server/readJson.js";

function request(headers = {}) {
  const req = new PassThrough();
  req.headers = headers;
  return req;
}

test("bounded JSON accepts an exact-limit body and rejects malformed JSON", async () => {
  const exact = request();
  const accepted = readJson(exact, 32);
  exact.end(`${" ".repeat(30)}{}`);
  assert.deepEqual(await accepted, {});

  const malformed = request();
  const rejected = readJson(malformed, 32);
  malformed.end("{");
  await assert.rejects(rejected, { message: "invalid_json", statusCode: 400 });
});

test("bounded JSON rejects duplicate names, including escaped aliases and nested objects", async () => {
  for (const wire of [
    '{"intent":0,"intent":1}',
    String.raw`{"intent":{"allowed":false,"\u0061llowed":true}}`,
    '{"items":[{"id":1},{"id":2,"id":3}]}'
  ]) {
    const input = request();
    const result = readJson(input);
    input.end(wire);
    await assert.rejects(result, { message: "ambiguous_json", statusCode: 400 });
  }
});

test("bounded JSON rejects malformed UTF-8 without changing valid split characters", async () => {
  const invalid = request();
  const invalidResult = readJson(invalid);
  invalid.end(Buffer.concat([Buffer.from('{"label":"'), Buffer.from([0xff]), Buffer.from('"}')]));
  await assert.rejects(invalidResult, { message: "invalid_json", statusCode: 400 });

  const bom = request();
  const bomResult = readJson(bom);
  bom.end(Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), Buffer.from("{}")]));
  await assert.rejects(bomResult, { message: "invalid_json", statusCode: 400 });

  const valid = request();
  const validResult = readJson(valid);
  const bytes = Buffer.from('{"label":"ĀRU 🌊"}');
  const split = bytes.indexOf(0xf0) + 1;
  valid.write(bytes.subarray(0, split));
  valid.end(bytes.subarray(split));
  assert.deepEqual(await validResult, { label: "ĀRU 🌊" });
});

test("advertised and streaming oversized bodies reject without resetting the socket", async () => {
  const advertised = request({ "content-length": "33" });
  await assert.rejects(readJson(advertised, 32), { message: "request_too_large", statusCode: 413 });
  assert.equal(advertised.destroyed, false);
  advertised.destroy();

  const streaming = request();
  const rejected = readJson(streaming, 32);
  streaming.write("x".repeat(33));
  await assert.rejects(rejected, { message: "request_too_large", statusCode: 413 });
  assert.equal(streaming.destroyed, false);
  streaming.destroy();
});

test("invalid size configuration is rejected", () => {
  assert.throws(() => readJson({}, 0), /positive safe integer/);
  assert.throws(() => readJson({}, Number.NaN), /positive safe integer/);
});
