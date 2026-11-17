// Synthetic canary keys only. Every key here is generated per test run and
// never written outside the test's temporary directory.
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

export function canaryKey() {
  const { privateKey, publicKey } = crypto.generateKeyPairSync("ed25519");
  return {
    pem: privateKey.export({ type: "pkcs8", format: "pem" }).toString(),
    publicPem: publicKey.export({ type: "spki", format: "pem" }).toString(),
    sha256: crypto.createHash("sha256").update(publicKey.export({ type: "spki", format: "der" })).digest("hex")
  };
}
export const iso = ms => new Date(Date.now() + ms).toISOString();
export const sha = s => crypto.createHash("sha256").update(s).digest("hex");

export function tempDir(t, prefix = "aml-trust-") {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  return dir;
}

export function configBody(roots, overrides = {}) {
  return {
    type: "aml-trust-config/1", version: 1, issued_at: iso(-60_000), expires_at: iso(3_600_000),
    root: { threshold: 2, keyids: roots.map(r => r.sha256) },
    trusted_keys: [], revoked_keys: [], policy_sha256: null, registry_sha256: null, profile_sha256: null,
    require_single_use: false, ...overrides
  };
}
