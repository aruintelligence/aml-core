import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";

import { compileSource } from "../index.js";

const timestamp = "2026-01-01T00:00:00.000Z";
const source = fs.readFileSync("examples/simple.aml", "utf8");

test("compileSource is reproducible when timestamp is fixed", () => {
  const first = compileSource(source, { timestamp });
  const second = compileSource(source, { timestamp });

  assert.deepEqual(first, second);
  assert.ok(first.renderDecisions.length > 0);
  for (const decision of first.renderDecisions) {
    assert.equal(decision.timestamp, timestamp);
  }
});
