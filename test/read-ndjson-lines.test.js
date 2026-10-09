import test from "node:test";
import assert from "node:assert/strict";
import { Readable } from "node:stream";
import { readNdjsonLines } from "../server/readNdjsonLines.js";

const limits = { max_line_bytes: 8, max_stream_bytes: 40 };
const collect = async (chunks, configured = limits) => {
  const lines = [];
  for await (const line of readNdjsonLines(Readable.from(chunks), configured)) lines.push(line);
  return lines;
};

test("bounded NDJSON reader handles split UTF-8 and CRLF without counting line separators", async () => {
  const utf8 = Buffer.from("ā\r\n");
  assert.deepEqual(await collect([utf8.subarray(0, 1), utf8.subarray(1, 3), utf8.subarray(3), "eight888\n", "tail"]),
    ["ā", "eight888", "tail"]);
});

test("bounded NDJSON reader rejects oversized lines while receiving chunks", async () => {
  await assert.rejects(collect(["12345", "67890", "\n"]), {
    statusCode: 413,
    message: "governance stream line exceeds max_line_bytes"
  });
  await assert.rejects(collect(["123456789\n"]), { statusCode: 413 });
});

test("bounded NDJSON reader caps cumulative bytes", async () => {
  await assert.rejects(collect(["1234\n", "5678\n"], { max_line_bytes: 8, max_stream_bytes: 9 }), {
    statusCode: 413,
    message: "governance stream exceeds max_stream_bytes"
  });
});
