import test from "node:test";
import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import { createInflightLimit } from "../server/inflightLimit.js";

test("in-flight slots are bounded and released on finish or disconnect", () => {
  const limit = createInflightLimit(1);
  const first = new EventEmitter();
  assert.equal(limit.acquire(first), true);
  assert.equal(limit.acquire(new EventEmitter()), false);
  first.emit("finish");
  first.emit("close");
  assert.equal(limit.acquire(new EventEmitter()), true);

  const other = createInflightLimit(1);
  const disconnected = new EventEmitter();
  assert.equal(other.acquire(disconnected), true);
  disconnected.emit("close");
  assert.equal(other.acquire(new EventEmitter()), true);
});

test("invalid in-flight ceilings fail at server construction", () => {
  assert.throws(() => createInflightLimit(0), /max_inflight_requests/);
  assert.throws(() => createInflightLimit(1.5), /max_inflight_requests/);
});
