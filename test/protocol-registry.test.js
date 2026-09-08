import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";

const discovery = JSON.parse(fs.readFileSync(new URL("../protocol/discovery.json", import.meta.url)));
const registry = JSON.parse(fs.readFileSync(new URL("../protocol/registry.json", import.meta.url)));
const levels = JSON.parse(fs.readFileSync(new URL("../conformance/levels.json", import.meta.url)));

test("discovery and registry share a wire version", () => {
  const overlap = discovery.wire_versions.filter((version) => registry.wire_versions.includes(version));
  assert.ok(overlap.length > 0);
});

test("federated compatibility level references registered capabilities", () => {
  for (const capability of levels.levels.federated.requires) {
    assert.ok(registry.capabilities.includes(capability), `${capability} must exist in protocol registry`);
  }
});

test("verifiable compatibility level references registered capabilities", () => {
  for (const capability of levels.levels.verifiable.requires) {
    assert.ok(registry.capabilities.includes(capability), `${capability} must exist in protocol registry`);
  }
});
