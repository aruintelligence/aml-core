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
