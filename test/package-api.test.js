import test from "node:test";
import assert from "node:assert/strict";

import { compileAML, ethicalRenderGate } from "../index.js";

test("package entry point exposes the public AML API", () => {
  assert.equal(typeof compileAML, "function");
  assert.equal(typeof ethicalRenderGate, "function");
});
