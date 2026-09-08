import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";

const registry = JSON.parse(fs.readFileSync(new URL("../BRAND_TRUST_ROOTS.json", import.meta.url), "utf8"));

test("canonical AML brand trust registry is explicit about bootstrap state", () => {
  assert.equal(registry.type, "aml-brand-trust-roots/1");
  assert.equal(registry.owner, "ĀRU Intelligence Inc.");
  assert.ok(["unprovisioned", "active", "rotating", "suspended"].includes(registry.status));
});

test("unprovisioned AML brand trust registry contains no active production key", () => {
  if (registry.status === "unprovisioned") {
    assert.deepEqual(registry.active_keys, []);
  }
});
