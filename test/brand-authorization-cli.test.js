import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { signBrandAuthorization } from "../runtime/brandAuthorization.js";
import { createRevocationRegistry } from "../runtime/revocationRegistry.js";

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

  // A caller-supplied replay time keeps `valid` but is untrusted: exit 3.
  const verified = run(["verify-brand-authorization", credentialPath], {
    env: { ...process.env, AML_VERIFY_AT: "2026-10-01T00:00:00.000Z", AML_EXPECTED_BRAND_ISSUER: "ĀRU Intelligence Inc." }
  });
  assert.equal(verified.status, 3, verified.stderr || verified.stdout);
  const result = JSON.parse(verified.stdout);
  assert.equal(result.valid, true);
  assert.equal(result.authorized, false);
  assert.equal(result.decision_use, "NOT AN AUTHORIZATION DECISION");
  assert.deepEqual(result.authorization.reasons, ["AML_AUTHZ_SIGNING_KEY_NOT_PINNED",
    "AML_AUTHZ_REVOCATION_NOT_CHECKED", "AML_AUTHZ_CALLER_CLOCK_UNTRUSTED"]);
  assert.equal(result.grantee, "Example Integrator LLC");
  assert.equal(result.clock_source, "caller_supplied");
});

test("verify-brand-authorization exits 0 only for the complete authorization decision", () => {
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), "aml-brand-cli-authz-"));
  const { privateKey } = crypto.generateKeyPairSync("ed25519");
  const day = 24 * 60 * 60 * 1000;
  const credential = signBrandAuthorization({
    grantee: "Example Integrator LLC", marks: ["ĀML™"], uses: ["official-compatible-badge"],
    issued_at: new Date(Date.now() - day).toISOString(), expires_at: new Date(Date.now() + day).toISOString()
  }, privateKey.export({ type: "pkcs8", format: "pem" }), { issuer: "Example Issuer" });
  const credentialPath = path.join(temp, "credential.json");
  const registryPath = path.join(temp, "registry.json");
  fs.writeFileSync(credentialPath, JSON.stringify(credential));
  fs.writeFileSync(registryPath, JSON.stringify(createRevocationRegistry()));
  const pinned = { AML_VERIFY_AT: "", AML_EXPECTED_BRAND_ISSUER: "Example Issuer",
    AML_TRUSTED_BRAND_KEY_SHA256: credential.public_key_sha256 };
  const verify = (env, ...extra) => {
    const out = run(["verify-brand-authorization", credentialPath, ...extra], { env: { ...process.env, ...env } });
    return { status: out.status, result: JSON.parse(out.stdout) };
  };
  const ok = verify(pinned, registryPath);
  assert.equal(ok.status, 0, JSON.stringify(ok.result));
  assert.equal(ok.result.authorized, true);
  assert.deepEqual(ok.result.authorization.reasons, ["AML_AUTHZ_ALLOW"]);
  const cases = {
    "no issuer pin": [{ ...pinned, AML_EXPECTED_BRAND_ISSUER: "" }, [registryPath], "AML_AUTHZ_ISSUER_NOT_PINNED"],
    "no key pin": [{ ...pinned, AML_TRUSTED_BRAND_KEY_SHA256: "" }, [registryPath], "AML_AUTHZ_SIGNING_KEY_NOT_PINNED"],
    "other key pin": [{ ...pinned, AML_TRUSTED_BRAND_KEY_SHA256: "0".repeat(64) }, [registryPath], "AML_AUTHZ_SIGNING_KEY_NOT_PINNED"],
    "no revocation registry": [pinned, [], "AML_AUTHZ_REVOCATION_NOT_CHECKED"],
    "stale caller clock": [{ ...pinned, AML_VERIFY_AT: new Date(Date.now() - 60000).toISOString() }, [registryPath], "AML_AUTHZ_CALLER_CLOCK_UNTRUSTED"],
    "future caller clock": [{ ...pinned, AML_VERIFY_AT: new Date(Date.now() + 60000).toISOString() }, [registryPath], "AML_AUTHZ_CALLER_CLOCK_UNTRUSTED"]
  };
  for (const [name, [env, extra, reason]] of Object.entries(cases)) {
    const out = verify(env, ...extra);
    assert.equal(out.result.valid, true, name);
    assert.equal(out.result.authorized, false, name);
    assert.equal(out.status, 3, name);
    assert.ok(out.result.authorization.reasons.includes(reason), `${name}: ${out.result.authorization.reasons}`);
  }
  const diagnostic = verify(pinned, registryPath, "--diagnostic-only");
  assert.equal(diagnostic.status, 0);
  assert.equal(diagnostic.result.authorized, false);
  assert.equal(diagnostic.result.diagnostic_only, true);
  assert.equal(diagnostic.result.decision_use, "NOT AN AUTHORIZATION DECISION");
  assert.equal(diagnostic.result.authorization.reasons[0], "AML_AUTHZ_DIAGNOSTIC_ONLY");
  const tampered = path.join(temp, "tampered.json");
  fs.writeFileSync(tampered, JSON.stringify({ ...credential, grantee: "Other" }));
  const bad = run(["verify-brand-authorization", tampered, registryPath], { env: { ...process.env, ...pinned } });
  assert.equal(bad.status, 1);
  assert.equal(JSON.parse(bad.stdout).authorized, false);
});

test("generic CLI defaults to current time and labels historical replay", () => {
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), "aml-brand-cli-time-"));
  const { privateKey } = crypto.generateKeyPairSync("ed25519");
  const credential = signBrandAuthorization({
    grantee: "Example Integrator LLC", marks: ["ĀML™"],
    issued_at: "2000-01-01T00:00:00Z", expires_at: "2001-01-01T00:00:00Z"
  }, privateKey.export({ type: "pkcs8", format: "pem" }));
  const credentialPath = path.join(temp, "credential.json");
  fs.writeFileSync(credentialPath, JSON.stringify(credential));
  const current = run(["verify-brand-authorization", credentialPath], {
    env: { ...process.env, AML_VERIFY_AT: "" }
  });
  assert.equal(current.status, 1);
  assert.equal(JSON.parse(current.stdout).reason, "expired");
  const replay = run(["verify-brand-authorization", credentialPath], {
    env: { ...process.env, AML_VERIFY_AT: "2000-06-01T00:00:00Z" }
  });
  assert.equal(replay.status, 3, "a historical replay is consistent but never authorized");
  assert.equal(JSON.parse(replay.stdout).valid, true);
  assert.equal(JSON.parse(replay.stdout).authorized, false);
  assert.equal(JSON.parse(replay.stdout).clock_source, "caller_supplied");
});
