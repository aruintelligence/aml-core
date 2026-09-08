import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";

function run(args, options = {}) {
  return spawnSync(process.execPath, ["bin/aml.js", ...args], {
    cwd: path.resolve(new URL("..", import.meta.url).pathname),
    encoding: "utf8",
    ...options
  });
}

test("CLI signs and verifies an AML brand authorization credential", () => {
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), "aml-brand-cli-"));
  const { privateKey } = crypto.generateKeyPairSync("ed25519");
  const keyPath = path.join(temp, "private.pem");
  const requestPath = path.join(temp, "request.json");
  const credentialPath = path.join(temp, "credential.json");

  fs.writeFileSync(keyPath, privateKey.export({ type: "pkcs8", format: "pem" }));
  fs.writeFileSync(requestPath, JSON.stringify({
    grantee: "Example Integrator LLC",
    marks: ["ĀML™"],
    uses: ["official-compatible-badge"],
    issued_at: "2026-09-08T00:00:00.000Z",
    expires_at: "2027-09-08T00:00:00.000Z",
    authorization_id: "cli-test-1",
    agreement_reference: "test-agreement"
  }));

  const signed = run(["sign-brand-authorization", requestPath, keyPath, credentialPath]);
  assert.equal(signed.status, 0, signed.stderr || signed.stdout);
  assert.equal(fs.existsSync(credentialPath), true);

  const verified = run(["verify-brand-authorization", credentialPath], {
    env: { ...process.env, AML_VERIFY_AT: "2026-10-01T00:00:00.000Z", AML_EXPECTED_BRAND_ISSUER: "ĀRU Intelligence Inc." }
  });
  assert.equal(verified.status, 0, verified.stderr || verified.stdout);
  const result = JSON.parse(verified.stdout);
  assert.equal(result.valid, true);
  assert.equal(result.grantee, "Example Integrator LLC");
});
