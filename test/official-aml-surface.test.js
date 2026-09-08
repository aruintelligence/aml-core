import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const required = [
  "TRADEMARKS.md",
  "COMMERCIAL.md",
  "OFFICIAL_MARKS.json",
  "OFFICIAL_AUTHORIZATIONS.json",
  "BRAND_TRUST_ROOTS.json",
  "TRADEMARK_REGISTRATION_PLAN.md",
  "docs/BRAND_KEY_OPERATIONS.md",
  "docs/official-aml.html",
  "docs/official-verify.html",
  "runtime/brandAuthorization.js",
  "runtime/brandTrust.js",
  "schema/brand-authorization.schema.json",
  "schema/brand-trust-roots.schema.json",
  "rfcs/0011-official-brand-authorization.md",
  "actions/verify-official/action.yml",
  "pilots/enterprise-30min/README.md",
  "protocol/aml-http.openapi.yaml"
];

test("official AML commercial/verification surface remains present", () => {
  for (const relative of required) {
    assert.equal(fs.existsSync(path.join(root, relative)), true, `Missing required official AML surface: ${relative}`);
  }
});

test("official AML trust registry does not contain a fake bootstrap production key", () => {
  const registry = JSON.parse(fs.readFileSync(path.join(root, "BRAND_TRUST_ROOTS.json"), "utf8"));
  if (registry.status === "unprovisioned") assert.deepEqual(registry.active_keys, []);
});
