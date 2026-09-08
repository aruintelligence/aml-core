import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import crypto from "node:crypto";

const registry = JSON.parse(fs.readFileSync("BRAND_TRUST_ROOTS.json", "utf8"));
const publicKeyPem = fs.readFileSync("protocol/keys/aru-aml-brand-prod-2026-09-08-01.pub.pem", "utf8");

function fingerprintPublicKey(pem) {
  const key = crypto.createPublicKey(pem);
  const der = key.export({ type: "spki", format: "der" });
  return crypto.createHash("sha256").update(der).digest("hex");
}

test("published AML production public key matches active ĀRU trust root", () => {
  const fingerprint = fingerprintPublicKey(publicKeyPem);
  const active = registry.active_keys.find((entry) => entry.key_id === "aru-aml-brand-prod-2026-09-08-01");
  assert.ok(active, "Production AML brand signing key must be present in active trust roots");
  assert.equal(active.public_key_sha256, fingerprint);
  assert.equal(registry.status, "active");
  assert.equal(registry.revoked_keys.some((entry) => entry.public_key_sha256 === fingerprint), false);
});
