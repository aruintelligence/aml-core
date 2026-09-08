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
  "protocol/aml-http.openapi.yaml",
  "keys/aru-aml-brand-prod-2026-09-08-01-public.pem"
];

const EXPECTED_PROD_KEY_ID = "aru-aml-brand-prod-2026-09-08-01";
const EXPECTED_PROD_FINGERPRINT = "eda0184568cb2110add5130d2a9fffaf53a77e0f2be311be414e7912ed69997c";

test("official AML commercial/verification surface remains present", () => {
  for (const relative of required) {
    assert.equal(fs.existsSync(path.join(root, relative)), true, `Missing required official AML surface: ${relative}`);
  }
});

test("official AML production trust registry is active and pinned to the published fingerprint", () => {
  const registry = JSON.parse(fs.readFileSync(path.join(root, "BRAND_TRUST_ROOTS.json"), "utf8"));
  assert.equal(registry.status, "active");
  assert.equal(registry.active_keys.length, 1);
  assert.equal(registry.active_keys[0].key_id, EXPECTED_PROD_KEY_ID);
  assert.equal(registry.active_keys[0].public_key_sha256, EXPECTED_PROD_FINGERPRINT);
  assert.match(registry.active_keys[0].public_key_sha256, /^[a-f0-9]{64}$/);
  assert.equal(registry.revoked_keys.some((entry) => entry.public_key_sha256 === EXPECTED_PROD_FINGERPRINT), false);
});

test("repository publishes the AML production public key but never the production private key", () => {
  const keysDir = path.join(root, "keys");
  const files = fs.readdirSync(keysDir);
  assert.equal(files.some((name) => /private/i.test(name)), false, "Private-key filename must never be committed under keys/");
  for (const name of files) {
    const full = path.join(keysDir, name);
    if (!fs.statSync(full).isFile()) continue;
    const body = fs.readFileSync(full, "utf8");
    assert.equal(body.includes("BEGIN PRIVATE KEY"), false, `Private key material detected in keys/${name}`);
  }
  const publicPem = fs.readFileSync(path.join(keysDir, "aru-aml-brand-prod-2026-09-08-01-public.pem"), "utf8");
  assert.match(publicPem, /BEGIN PUBLIC KEY/);
});
