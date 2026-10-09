import test from "node:test";
import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import { writeNdjson } from "../server/writeNdjson.js";

class SlowResponse extends EventEmitter {
  destroyed = false;
  writableEnded = false;
  lines = [];

  write(line) {
    this.lines.push(line);
    return false;
  }
}

test("NDJSON writer waits for drain before continuing a slow response", async () => {
  const response = new SlowResponse();
  let finished = false;
  const pending = writeNdjson(response, { decision: "allow" }).then(() => { finished = true; });
  await Promise.resolve();
  assert.equal(finished, false);
  assert.deepEqual(response.lines, ['{"decision":"allow"}\n']);
  response.emit("drain");
  await pending;
  assert.equal(finished, true);
  assert.equal(response.listenerCount("close"), 0);
  assert.equal(response.listenerCount("error"), 0);
});

test("NDJSON writer stops when a slow client disconnects", async () => {
  const response = new SlowResponse();
  const pending = writeNdjson(response, { decision: "suppress" });
  response.destroyed = true;
  response.emit("close");
  await assert.rejects(pending, /response_closed/);
  assert.equal(response.listenerCount("drain"), 0);
  await assert.rejects(writeNdjson(response, {}), /response_closed/);
});

test("NDJSON writer treats a transport error as a closed response", async () => {
  const response = new SlowResponse();
  const pending = writeNdjson(response, { decision: "allow" });
  response.emit("error", new Error("socket error"));
  await assert.rejects(pending, { code: "AML_RESPONSE_CLOSED" });
  assert.equal(response.listenerCount("drain"), 0);
  assert.equal(response.listenerCount("close"), 0);
});
