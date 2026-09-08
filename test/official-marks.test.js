import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";

const registry = JSON.parse(fs.readFileSync(new URL("../OFFICIAL_MARKS.json", import.meta.url), "utf8"));

test("official marks registry identifies the owner and commercial contact", () => {
  assert.equal(registry.owner, "ĀRU Intelligence Inc.");
  assert.equal(registry.commercial_contact, "Office@aruintelligence.com");
  assert.ok(Array.isArray(registry.marks));
  assert.ok(registry.marks.length >= 5);
});

test("unregistered marks are not represented as federally registered", () => {
  for (const entry of registry.marks) {
    if (entry.registration == null) {
      assert.notEqual(entry.status, "registered");
      assert.notEqual(entry.status, "federally_registered");
    }
  }
});

test("compatibility marks explicitly separate technical conformance from official branding", () => {
  const compatibilityMarks = registry.marks.filter((entry) => entry.mark.includes("Compatible"));
  assert.ok(compatibilityMarks.length >= 2);
  for (const entry of compatibilityMarks) {
    assert.match(entry.note, /authorization/i);
    assert.match(entry.note, /technical conformance/i);
  }
});
