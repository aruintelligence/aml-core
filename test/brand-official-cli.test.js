import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";
import { signBrandAuthorization } from "../runtime/brandAuthorization.js";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

function run(args, env = {}) {
  return spawnSync(process.execPath, ["bin/aml-brand-verify.js", ...args], {
    cwd: repoRoot,
    encoding: "utf8",
    env: { ...process.env, ...env }
  });
}

test("official brand verifier rejects self-signed credential when canonical-style trust registry has no key", () => {
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), "aml-official-brand-"));
  const { privateKey } = crypto.generateKeyPairSync("ed25519");
  const credential = signBrandAuthorization({
    grantee: "Example Integrator LLC",
    marks: ["ĀML Compatible™"],
    uses: ["official-compatible-badge"],
    authorization_id: "official-cli-reject"
  }, privateKey.export({ type: "pkcs8", format: "pem" }), { issuer: "ĀRU Intelligence Inc." });

  const credentialPath = path.join(temp, "credential.json");
  const trustPath = path.join(temp, "trust.json");
  fs.writeFileSync(credentialPath, JSON.stringify(credential));
  fs.writeFileSync(trustPath, JSON.stringify({
    type: "aml-brand-trust-roots/1",
    owner: "ĀRU Intelligence Inc.",
    status: "unprovisioned",
    active_keys: [],
    revoked_keys: []
  }));

  const result = run([credentialPath, trustPath]);
  assert.equal(result.status, 1);
  const output = JSON.parse(result.stdout);
  assert.equal(output.official, false);
  assert.equal(output.reason, "untrusted_signing_key");
});

test("official brand verifier accepts credential only when signer is an active trust root", () => {
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), "aml-official-brand-"));
  const { privateKey } = crypto.generateKeyPairSync("ed25519");
  const credential = signBrandAuthorization({
    grantee: "Example Integrator LLC",
    marks: ["ĀML Compatible™"],
    uses: ["official-compatible-badge"],
    authorization_id: "official-cli-accept"
  }, privateKey.export({ type: "pkcs8", format: "pem" }), { issuer: "ĀRU Intelligence Inc." });

  const credentialPath = path.join(temp, "credential.json");
  const trustPath = path.join(temp, "trust.json");
  fs.writeFileSync(credentialPath, JSON.stringify(credential));
  fs.writeFileSync(trustPath, JSON.stringify({
    type: "aml-brand-trust-roots/1",
    owner: "ĀRU Intelligence Inc.",
    status: "active",
    active_keys: [{
      key_id: "test-only-root",
      public_key_sha256: credential.public_key_sha256,
      purpose: "test-only"
    }],
    revoked_keys: []
  }));

  const result = run([credentialPath, trustPath]);
  assert.equal(result.status, 0, result.stderr || result.stdout);
  const output = JSON.parse(result.stdout);
  assert.equal(output.valid, true);
  assert.equal(output.official, true);
  assert.equal(output.trust_root.key_id, "test-only-root");
});
