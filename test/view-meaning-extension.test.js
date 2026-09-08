import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";

const manifest = JSON.parse(fs.readFileSync("extensions/view-meaning/manifest.json", "utf8"));
const popup = fs.readFileSync("extensions/view-meaning/popup.js", "utf8");

test("View Meaning extension keeps a narrow permission surface", () => {
  assert.equal(manifest.manifest_version, 3);
  assert.deepEqual([...manifest.permissions].sort(), ["activeTab", "scripting"].sort());
  assert.deepEqual(manifest.host_permissions, ["https://raw.githubusercontent.com/aruintelligence/aml-core/*"]);
  assert.equal(manifest.permissions.includes("history"), false);
  assert.equal(manifest.permissions.includes("tabs"), false);
});

test("View Meaning extension performs local receipt and official-brand verification", () => {
  assert.match(popup, /verifyReceipt/);
  assert.match(popup, /verifyBrandCredential/);
  assert.match(popup, /crypto\.subtle/);
  assert.match(popup, /BRAND_TRUST_ROOTS\.json/);
  assert.match(popup, /untrusted_signing_key/);
  assert.match(popup, /receipt_hash_mismatch/);
});

test("View Meaning extension surfaces purpose and human-context fields", () => {
  assert.match(popup, /Declared purpose/);
  assert.match(popup, /Consent \/ privacy \/ accessibility context/);
  assert.match(popup, /consent_granted/);
  assert.match(popup, /privacy_consent/);
  assert.match(popup, /prefers_reduced_motion/);
  assert.match(popup, /high_contrast_required/);
  assert.match(popup, /attention_budget_remaining/);
});
