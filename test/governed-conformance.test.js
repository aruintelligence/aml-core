import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import { evaluateConformanceLevel } from "../index.js";

const registry = JSON.parse(fs.readFileSync(new URL("../protocol/registry.json", import.meta.url)));
const levels = JSON.parse(fs.readFileSync(new URL("../conformance/levels.json", import.meta.url)));

test("governed conformance requirements are registered", () => {
  for (const capability of levels.levels.governed.requires) {
    assert.ok(registry.capabilities.includes(capability), `${capability} must exist in the AML protocol registry`);
  }
});

test("full registered capability set reaches governed conformance", () => {
  assert.equal(evaluateConformanceLevel(registry.capabilities).level, "governed");
});
