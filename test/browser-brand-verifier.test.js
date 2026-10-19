import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import { signBrandAuthorization } from "../runtime/brandAuthorization.js";

test("public browser verifier rejects expired, future, and inactive-root credentials", async () => {
  const page = fs.readFileSync(new URL("../docs/official-verify.html", import.meta.url), "utf8");
  const script = page.match(/<script type="module">([\s\S]*?)<\/script>/)?.[1];
  assert.ok(script, "browser verifier module must be present");

  const elements = new Map();
  const element = (id) => {
    if (!elements.has(id)) elements.set(id, { value: "", textContent: "", className: "", addEventListener(_event, fn) { this.click = fn; } });
    return elements.get(id);
  };
  const { privateKey } = crypto.generateKeyPairSync("ed25519");
  const pem = privateKey.export({ type: "pkcs8", format: "pem" });
  const issue = (times = {}) => signBrandAuthorization({
    grantee: "Example Integrator LLC", marks: ["ĀML™"], ...times
  }, pem);
  const current = issue();
  const registry = {
    type: "aml-brand-trust-roots/1", owner: "ĀRU Intelligence Inc.",
    status: "active",
    active_keys: [{ public_key_sha256: current.public_key_sha256 }], revoked_keys: []
  };
  const AsyncFunction = Object.getPrototypeOf(async function () {}).constructor;
  await new AsyncFunction("crypto", "document", "fetch", "atob", "TextEncoder", script)(
    crypto.webcrypto,
    { getElementById: element },
    async () => ({ ok: true, json: async () => registry }),
    globalThis.atob,
    TextEncoder
  );
  const click = async (credential) => {
    element("credential").value = JSON.stringify(credential);
    await element("verify").click();
    return JSON.parse(element("details").textContent);
  };

  const expired = await click(issue({ issued_at: "2000-01-01T00:00:00Z", expires_at: "2001-01-01T00:00:00Z" }));
  assert.equal(expired.credential_reason, "expired");
  assert.equal(expired.official, false);
  const future = await click(issue({ issued_at: "2100-01-01T00:00:00Z" }));
  assert.equal(future.credential_reason, "not_yet_issued");
  assert.equal(future.official, false);

  registry.active_keys[0].not_after = "2001-01-01T00:00:00Z";
  const expiredRoot = await click(current);
  assert.equal(expiredRoot.trust_reason, "signing_key_expired");
  assert.equal(expiredRoot.official, false);
  delete registry.active_keys[0].not_after;
  registry.active_keys[0].not_before = "2100-01-01T00:00:00Z";
  assert.equal((await click(current)).trust_reason, "signing_key_not_yet_valid");
  registry.active_keys[0].not_before = "invalid";
  assert.equal((await click(current)).trust_reason, "invalid_trust_registry");
  delete registry.active_keys[0].not_before;
  registry.active_keys.push({ public_key_sha256: "other", not_before: "invalid" });
  assert.equal((await click(current)).trust_reason, "invalid_trust_registry");
  registry.active_keys.pop();
  registry.status = "suspended";
  assert.equal((await click(current)).trust_reason, "trust_registry_inactive");
  registry.status = "active";
  const active = await click(current);
  assert.equal(active.official, true);
  assert.equal(active.clock_source, "local_system");
  assert.equal(active.credential_revocation_checked, false);
});
