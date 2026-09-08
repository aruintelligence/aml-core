import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import { canonicalJSONStringify } from "../index.js";

const vectors = JSON.parse(fs.readFileSync(new URL("../protocol/test-vectors.json", import.meta.url)));

test("AML canonical JSON matches published golden vectors", () => {
  for (const vector of vectors.canonical_json) {
    assert.equal(canonicalJSONStringify(vector.input), vector.expected, vector.name);
  }
});
