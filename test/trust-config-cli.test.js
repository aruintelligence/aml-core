// CLI trust-config mode and single-use verifiers. These cases confirm
// that an enrolled host refuses a rewritten pin, a revoked key, an older
// signed config, and replay when a single-use store is required.
// Synthetic canary keys only.
import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { executeAccountableIntent, signExecutionReceipt } from "../compiler/accountablePipeline.js";
import { signBrandAuthorization } from "../runtime/brandAuthorization.js";
import { signPolicyPack } from "../runtime/policyPack.js";
import { createRevocationRegistry, revokeArtifact, revocationRegistryFingerprint } from "../runtime/revocationRegistry.js";
import { canaryKey, configBody, iso, tempDir } from "./fixtures/trust-config/helpers.mjs";

const ROOT = path.resolve(new URL("..", import.meta.url).pathname);
function aml(args, env = {}) {
  const clean = { ...process.env };
  for (const name of ["AML_TRUST_STATE_DIR", "AML_VERIFY_AT", "AML_TRUSTED_BRAND_KEY_SHA256", "AML_TRUSTED_REVOCATION_REGISTRY_SHA256", "AML_EXPECTED_BRAND_ISSUER"]) delete clean[name];
  const out = spawnSync(process.execPath, ["bin/aml.js", ...args], { cwd: ROOT, encoding: "utf8", env: { ...clean, ...env } });
  let json = null; try { json = JSON.parse(out.stdout); } catch { /* text output */ }
  return { status: out.status, json, stdout: out.stdout, stderr: out.stderr };
}

function world(t) {
  const dir = tempDir(t, "aml-trust-cli-");
  const roots = [canaryKey(), canaryKey(), canaryKey()];
  const rootFiles = roots.map((r, i) => { const f = path.join(dir, `root${i}.pem`); fs.writeFileSync(f, r.pem); return f; });
  const stateDir = path.join(dir, "state");
  const init = aml(["trust-init", stateDir, "--threshold", "2", "--root-key-sha256", roots.map(r => r.sha256).join(",")]);
  assert.equal(init.status, 0, init.stderr);
  let n = 0;
  const config = (overrides, signers = [0, 1]) => {
    n += 1;
    const bodyFile = path.join(dir, `body${n}.json`); const envFile = path.join(dir, `config${n}.json`);
    fs.writeFileSync(bodyFile, JSON.stringify(configBody(roots, overrides)));
    const signed = aml(["trust-sign", bodyFile, signers.map(i => rootFiles[i]).join(","), envFile]);
    assert.equal(signed.status, 0, signed.stderr);
    return envFile;
  };
  const receipt = (key, label = "r") => {
    const r = executeAccountableIntent({ transmission: label, nodes: [{ type: "engram", identifier: "c",
      properties: { purpose: "p", attention_cost: 1, restoration_value: 5 } }] }, { timestamp: "2030-01-01T00:00:00.000Z" });
    const f = path.join(dir, `${label}.json`); fs.writeFileSync(f, JSON.stringify(signExecutionReceipt(r, key.pem))); return f;
  };
  return { dir, roots, stateDir, config, receipt, env: { AML_TRUST_STATE_DIR: stateDir } };
}

test("trust CLI: trust-verify exits 0 only for a threshold-signed, unexpired, non-rolled-back config", t => {
  const w = world(t);
  const good = w.config({ version: 1 });
  const ok = aml(["trust-verify", "--trust-config", good], w.env);
  assert.equal(ok.status, 0, ok.stdout);
  assert.equal(ok.json.authorized, true);
  assert.equal(aml(["trust-verify", "--trust-config", w.config({ version: 2 }, [0])], w.env).status, 3, "one root signature");
  assert.equal(aml(["trust-verify", "--trust-config", w.config({ version: 3, issued_at: iso(-7_200_000), expires_at: iso(-1) })], w.env).status, 3, "expired");
  assert.equal(aml(["trust-verify", "--trust-config", good], { ...w.env, AML_VERIFY_AT: iso(0) }).status, 3, "caller time");
  assert.equal(aml(["trust-verify", "--trust-config", good]).status, 3, "no enrolled state: fail closed");
  assert.equal(aml(["trust-verify"], w.env).status, 3, "enrolled but no config");
});

test("trust CLI X1: on an enrolled host, rewriting --trusted-key-sha256 to the attacker key no longer authorizes", t => {
  const w = world(t);
  const owner = canaryKey(); const attacker = canaryKey();
  const cfg = w.config({ trusted_keys: [{ keyid: owner.sha256, roles: ["receipt"] }] });
  const forged = w.receipt(attacker, "forged");
  // Without enrollment the old explicit-pin path is unchanged (documented LIMIT).
  assert.equal(aml(["verify-signed-receipt", forged, "--trusted-key-sha256", attacker.sha256]).status, 0);
  const noConfig = aml(["verify-signed-receipt", forged, "--trusted-key-sha256", attacker.sha256], w.env);
  assert.equal(noConfig.status, 3);
  assert.ok(noConfig.json.authorization.reasons.includes("AML_AUTHZ_TRUST_CONFIG_NOT_TRUSTED"));
  const withConfig = aml(["verify-signed-receipt", forged, "--trusted-key-sha256", attacker.sha256, "--trust-config", cfg], w.env);
  assert.equal(withConfig.status, 3);
  assert.deepEqual(withConfig.json.authorization.reasons, ["AML_AUTHZ_SIGNING_KEY_NOT_PINNED"]);
  // Positive control: the owner key from the config authorizes with or without a matching flag pin.
  const genuine = w.receipt(owner, "genuine");
  assert.equal(aml(["verify-signed-receipt", genuine, "--trust-config", cfg], w.env).status, 0);
  assert.equal(aml(["verify-signed-receipt", genuine, "--trust-config", cfg, "--trusted-key-sha256", owner.sha256], w.env).status, 0);
  assert.equal(aml(["verify-signed-receipt", genuine, "--trust-config", cfg, "--trusted-key-sha256", attacker.sha256], w.env).status, 3, "pins AND");
  // Role scoping: a receipt key is not a policy-pack or build-attestation key.
  assert.equal(aml(["verify-signed-receipt", genuine, "--trust-config", cfg, "--diagnostic-only"], w.env).json.authorized, false);
});

test("trust CLI X2: a stolen signing key is cut off by a revoking config version", t => {
  const w = world(t);
  const stolen = canaryKey(); const replacement = canaryKey();
  const v1 = w.config({ version: 1, trusted_keys: [{ keyid: stolen.sha256, roles: ["receipt"] }] });
  const thiefReceipt = w.receipt(stolen, "thief");
  assert.equal(aml(["verify-signed-receipt", thiefReceipt, "--trust-config", v1], w.env).status, 0, "before revocation the stolen key works");
  const v2 = w.config({ version: 2, trusted_keys: [{ keyid: replacement.sha256, roles: ["receipt"] }], revoked_keys: [stolen.sha256] });
  const after = aml(["verify-signed-receipt", thiefReceipt, "--trust-config", v2, "--trusted-key-sha256", stolen.sha256], w.env);
  assert.equal(after.status, 3);
  assert.deepEqual(after.json.authorization.reasons, ["AML_AUTHZ_SIGNING_KEY_NOT_PINNED"]);
  // The thief replays v1 (still validly signed): rollback refused.
  const rolled = aml(["verify-signed-receipt", thiefReceipt, "--trust-config", v1], w.env);
  assert.equal(rolled.status, 3);
  assert.ok(rolled.json.trust.reasons.includes("not_rolled_back"));
  assert.equal(aml(["verify-signed-receipt", w.receipt(replacement, "new"), "--trust-config", v2], w.env).status, 0);
});

test("trust CLI X3: brand registry pin comes from the signed config; rolling back config or registry is refused", t => {
  const w = world(t);
  const brandKey = canaryKey();
  const day = 86_400_000;
  const credential = signBrandAuthorization({ grantee: "Example Integrator LLC", marks: ["ĀML™"], uses: ["official-compatible-badge"],
    issued_at: iso(-day), expires_at: iso(day) }, brandKey.pem, { issuer: "Example Issuer" });
  const credFile = path.join(w.dir, "cred.json"); fs.writeFileSync(credFile, JSON.stringify(credential));
  const r1 = createRevocationRegistry();
  const r2 = revokeArtifact(r1, credential.credential_hash, { reason: "compromised", revoked_at: iso(-1000) });
  const r1File = path.join(w.dir, "r1.json"); fs.writeFileSync(r1File, JSON.stringify(r1));
  const r2File = path.join(w.dir, "r2.json"); fs.writeFileSync(r2File, JSON.stringify(r2));
  const keys = [{ keyid: brandKey.sha256, roles: ["brand-authorization"] }];
  const v1 = w.config({ version: 1, trusted_keys: keys, registry_sha256: revocationRegistryFingerprint(r1) });
  const env = { ...w.env, AML_EXPECTED_BRAND_ISSUER: "Example Issuer" };
  assert.equal(aml(["verify-brand-authorization", credFile, r1File, "--trust-config", v1], env).status, 0);
  const v2 = w.config({ version: 2, trusted_keys: keys, registry_sha256: revocationRegistryFingerprint(r2) });
  // Old registry with the new config: registry pin mismatch.
  const oldRegistry = aml(["verify-brand-authorization", credFile, r1File, "--trust-config", v2], env);
  assert.equal(oldRegistry.status, 3);
  assert.ok(oldRegistry.json.authorization.reasons.includes("AML_AUTHZ_REVOCATION_REGISTRY_NOT_PINNED"));
  // Old registry + old config + attacker env pin for the old registry: rollback refused.
  const rollback = aml(["verify-brand-authorization", credFile, r1File, "--trust-config", v1],
    { ...env, AML_TRUSTED_REVOCATION_REGISTRY_SHA256: revocationRegistryFingerprint(r1), AML_TRUSTED_BRAND_KEY_SHA256: brandKey.sha256 });
  assert.equal(rollback.status, 3);
  assert.ok(rollback.json.authorization.reasons.includes("AML_AUTHZ_TRUST_CONFIG_NOT_TRUSTED"));
  // Current registry: the credential is revoked, so not authorized either.
  assert.notEqual(aml(["verify-brand-authorization", credFile, r2File, "--trust-config", v2], env).status, 0);
});

test("trust CLI X4: --single-use-store makes a pinned artifact authorize at most once; require_single_use enforces it", t => {
  const w = world(t);
  const owner = canaryKey();
  const file = w.receipt(owner, "once");
  const store = path.join(w.dir, "store");
  const first = aml(["verify-signed-receipt", file, "--trusted-key-sha256", owner.sha256, "--single-use-store", store]);
  assert.equal(first.status, 0, first.stdout);
  const second = aml(["verify-signed-receipt", file, "--trusted-key-sha256", owner.sha256, "--single-use-store", store]);
  assert.equal(second.status, 3);
  assert.deepEqual(second.json.authorization.reasons, ["AML_AUTHZ_ALREADY_CONSUMED"]);
  // A denied attempt does not burn the artifact.
  const other = w.receipt(owner, "other");
  assert.equal(aml(["verify-signed-receipt", other, "--trusted-key-sha256", "0".repeat(64), "--single-use-store", store]).status, 3);
  assert.equal(aml(["verify-signed-receipt", other, "--trusted-key-sha256", owner.sha256, "--single-use-store", store]).status, 0);
  // A config that requires single use refuses a verifier invoked without a store.
  const cfg = w.config({ require_single_use: true, trusted_keys: [{ keyid: owner.sha256, roles: ["receipt"] }] });
  const third = w.receipt(owner, "third");
  const noStore = aml(["verify-signed-receipt", third, "--trust-config", cfg], w.env);
  assert.equal(noStore.status, 3);
  assert.deepEqual(noStore.json.authorization.reasons, ["AML_AUTHZ_SINGLE_USE_STORE_REQUIRED"]);
  assert.equal(aml(["verify-signed-receipt", third, "--trust-config", cfg, "--single-use-store", store], w.env).status, 0);
  assert.equal(aml(["verify-signed-receipt", third, "--trust-config", cfg, "--single-use-store", store], w.env).status, 3);
});

test("trust CLI: verify-receipt and replay-receipt honour trust-config mode and single use", t => {
  const w = world(t);
  const owner = canaryKey();
  const cfg = w.config({});
  const r = executeAccountableIntent({ transmission: "plain", nodes: [{ type: "engram", identifier: "c",
    properties: { purpose: "p", attention_cost: 1, restoration_value: 5 } }] }, { timestamp: "2030-01-01T00:00:00.000Z" });
  const file = path.join(w.dir, "plain.json"); fs.writeFileSync(file, JSON.stringify(r));
  assert.equal(aml(["verify-receipt", file, "--expected-sha256", r.receipt_sha256], w.env).status, 3, "enrolled: config required");
  assert.equal(aml(["verify-receipt", file, "--expected-sha256", r.receipt_sha256, "--trust-config", cfg], w.env).status, 0);
  assert.equal(aml(["verify-receipt", file, "--trust-config", cfg], w.env).status, 3, "artifact pin still required");
  const store = path.join(w.dir, "s2");
  assert.equal(aml(["replay-receipt", file, "--expected-sha256", r.receipt_sha256, "--single-use-store", store]).status, 0);
  assert.equal(aml(["replay-receipt", file, "--expected-sha256", r.receipt_sha256, "--single-use-store", store]).status, 3);
  void owner;
});

test("trust CLI: verify-policy-pack needs the policy-pack role and, when set, the config's policy digest", t => {
  const w = world(t);
  const policyKey = canaryKey(); const receiptKey = canaryKey();
  const pack = signPolicyPack({ id: "tc_pack", issuer: "tc", policies: ["restorative_v1"] }, policyKey.pem, { signer: "tc" });
  const other = signPolicyPack({ id: "tc_pack_other", issuer: "tc", policies: ["restorative_v1"] }, policyKey.pem, { signer: "tc" });
  const packFile = path.join(w.dir, "pack.json"); fs.writeFileSync(packFile, JSON.stringify(pack));
  const otherFile = path.join(w.dir, "other.json"); fs.writeFileSync(otherFile, JSON.stringify(other));
  const keys = [{ keyid: policyKey.sha256, roles: ["policy-pack"] }, { keyid: receiptKey.sha256, roles: ["receipt"] }];
  const cfg = w.config({ version: 1, trusted_keys: keys, policy_sha256: pack.pack_sha256 });
  assert.equal(aml(["verify-policy-pack", packFile, "--trust-config", cfg], w.env).status, 0);
  const wrongPack = aml(["verify-policy-pack", otherFile, "--trust-config", cfg], w.env);
  assert.equal(wrongPack.status, 3);
  assert.deepEqual(wrongPack.json.authorization.reasons, ["AML_AUTHZ_POLICY_NOT_PINNED"]);
  // A key trusted only for receipts cannot sign policy packs.
  const byReceiptKey = signPolicyPack({ id: "tc_pack", issuer: "tc", policies: ["restorative_v1"] }, receiptKey.pem, { signer: "tc" });
  const rk = path.join(w.dir, "rk.json"); fs.writeFileSync(rk, JSON.stringify(byReceiptKey));
  const roleMismatch = aml(["verify-policy-pack", rk, "--trust-config", cfg], w.env);
  assert.equal(roleMismatch.status, 3);
  assert.ok(roleMismatch.json.authorization.reasons.includes("AML_AUTHZ_SIGNING_KEY_NOT_PINNED"));
});
