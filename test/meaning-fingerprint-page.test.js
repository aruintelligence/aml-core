import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";

const page = fs.readFileSync("docs/meaning-fingerprint.html", "utf8");
const browser = fs.readFileSync("docs/aml-meaning-fingerprint.js", "utf8");
const publication = fs.readFileSync("publications/MEANING_FINGERPRINT.md", "utf8");

test("live Meaning Fingerprint challenge exposes the real protocol and CI path", () => {
  for (const required of [
    "aml-meaning-fingerprint/1",
    "aml-meaning-material/1",
    "SAME COMPILED MEANING",
    "MEANING CHANGED",
    "actions/meaning-lock@main",
    "aml-meaning-fingerprint.js"
  ]) assert.ok(page.includes(required), `missing ${required}`);
});

test("browser Meaning Fingerprint composes the browser compiler and canonicalizer", () => {
  assert.ok(browser.includes('from "./aml-browser.js"'));
  assert.ok(browser.includes('from "./aml-browser-integrity.js"'));
  assert.ok(browser.includes('protocol: MATERIAL_PROTOCOL'));
  assert.ok(browser.includes('sha256Browser(canonical)'));
});

test("public protocol explainer links to the live challenge and preserves evidence boundary", () => {
  assert.ok(publication.includes("https://aruintelligence.github.io/aml-core/meaning-fingerprint.html"));
  assert.ok(publication.includes("does **not** prove"));
  assert.ok(publication.includes("not a ratified standard"));
});
