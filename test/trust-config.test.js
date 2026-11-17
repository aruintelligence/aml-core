// Signed, versioned trust config: threshold root signatures, rollback and fork
// protection persisted locally, expiry on the verifier's own clock with a
// persisted time floor, root rotation, sticky revocation. Synthetic keys only.
import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { spawn } from "node:child_process";
import {
  signTrustConfig, evaluateTrustConfig, evaluateTrustConfigAll, initTrustState, readTrustState, trustConfigTrustsKey,
  trustConfigPinMatches, trustConfigRequiresSingleUse, enrolledTrustStateDirs, validateTrustConfigBody
} from "../runtime/trustConfig.js";
import { canaryKey, configBody, iso, sha, tempDir } from "./fixtures/trust-config/helpers.mjs";

function setup(t) {
  const roots = [canaryKey(), canaryKey(), canaryKey()];
  const stateDir = path.join(tempDir(t), "state");
  initTrustState(stateDir, { threshold: 2, rootKeyids: roots.map(r => r.sha256) });
  return { roots, stateDir };
}

test("trust config: 2-of-3 root signatures are trusted; one signature, a repeated signature or a non-root signature are not", t => {
  const { roots, stateDir } = setup(t);
  const signer = canaryKey();
  const body = configBody(roots, { trusted_keys: [{ keyid: signer.sha256, roles: ["receipt"] }] });
  const one = signTrustConfig(body, [roots[0].pem]);
  assert.deepEqual(evaluateTrustConfig(one, { stateDir }).reasons, ["root_threshold_met", "state_persisted"]);
  const repeated = { ...one, signatures: [one.signatures[0], one.signatures[0]] };
  assert.equal(evaluateTrustConfig(repeated, { stateDir }).checks.root_threshold_met, false);
  const outsider = canaryKey();
  const withOutsider = signTrustConfig(body, [roots[0].pem, outsider.pem]);
  assert.equal(evaluateTrustConfig(withOutsider, { stateDir }).checks.root_threshold_met, false);
  // A signature whose claimed keyid is a root key but whose key material is not.
  const spoofed = { ...withOutsider, signatures: [withOutsider.signatures[0], { ...withOutsider.signatures[1], keyid: roots[1].sha256 }] };
  assert.equal(evaluateTrustConfig(spoofed, { stateDir }).checks.root_threshold_met, false);
  const ok = evaluateTrustConfig(signTrustConfig(body, [roots[0].pem, roots[2].pem]), { stateDir });
  assert.equal(ok.trusted, true, ok.reasons.join());
  assert.deepEqual(ok.reasons, []);
  assert.equal(trustConfigTrustsKey(ok, signer.sha256, "receipt"), true);
  assert.equal(trustConfigTrustsKey(ok, signer.sha256, "policy-pack"), false, "roles are scoped");
  assert.equal(trustConfigTrustsKey(ok, outsider.sha256, "receipt"), false);
});

test("trust config: editing the signed body after signing breaks the threshold", t => {
  const { roots, stateDir } = setup(t);
  const attacker = canaryKey();
  const env = signTrustConfig(configBody(roots), [roots[0].pem, roots[1].pem]);
  const tampered = { ...env, signed: { ...env.signed, trusted_keys: [{ keyid: attacker.sha256, roles: ["receipt"] }] } };
  const d = evaluateTrustConfig(tampered, { stateDir });
  assert.equal(d.trusted, false);
  assert.equal(d.checks.root_threshold_met, false);
});

test("trust config: rollback to a lower version and a same-version fork are refused; the same config is idempotent", t => {
  const { roots, stateDir } = setup(t);
  const v1 = signTrustConfig(configBody(roots, { version: 1 }), [roots[0].pem, roots[1].pem]);
  const v2 = signTrustConfig(configBody(roots, { version: 2 }), [roots[0].pem, roots[1].pem]);
  assert.equal(evaluateTrustConfig(v1, { stateDir }).trusted, true);
  assert.equal(evaluateTrustConfig(v2, { stateDir }).trusted, true);
  assert.equal(evaluateTrustConfig(v2, { stateDir }).trusted, true, "re-presenting the current version is fine");
  const back = evaluateTrustConfig(v1, { stateDir });
  assert.equal(back.trusted, false);
  assert.ok(back.reasons.includes("not_rolled_back"));
  const fork = signTrustConfig(configBody(roots, { version: 2, policy_sha256: sha("other") }), [roots[1].pem, roots[2].pem]);
  const forked = evaluateTrustConfig(fork, { stateDir });
  assert.equal(forked.trusted, false);
  assert.deepEqual(forked.reasons, ["no_version_fork", "state_persisted"]);
  assert.equal(readTrustState(stateDir).latest.version, 2);
});

test("trust config: expiry, not-yet-valid and any caller-supplied time fail closed", t => {
  const { roots, stateDir } = setup(t);
  const sign = o => signTrustConfig(configBody(roots, o), [roots[0].pem, roots[1].pem]);
  assert.ok(evaluateTrustConfig(sign({ issued_at: iso(-7_200_000), expires_at: iso(-1_000) }), { stateDir }).reasons.includes("not_expired"));
  assert.ok(evaluateTrustConfig(sign({ issued_at: iso(600_000), expires_at: iso(7_200_000) }), { stateDir }).reasons.includes("issued_not_in_future"));
  const fresh = sign({});
  const withCallerTime = evaluateTrustConfig(fresh, { stateDir, callerTime: iso(-1_000) });
  assert.deepEqual(withCallerTime.reasons, ["caller_time_absent", "state_persisted"]);
  // There is no `now` option: passing one is ignored, the local clock decides.
  const expired = sign({ version: 1, issued_at: iso(-7_200_000), expires_at: iso(-1_000) });
  assert.equal(evaluateTrustConfig(expired, { stateDir, now: iso(-3_600_000) }).trusted, false);
});

test("trust config: a local clock earlier than the persisted time floor fails closed (clock rollback)", t => {
  const { roots, stateDir } = setup(t);
  const v1 = signTrustConfig(configBody(roots), [roots[0].pem, roots[1].pem]);
  assert.equal(evaluateTrustConfig(v1, { stateDir }).trusted, true);
  // Simulate "the clock was wound back": the floor (accepted_at) is now ahead of the clock.
  const file = path.join(stateDir, "versions", "v000000000001.json");
  const rec = JSON.parse(fs.readFileSync(file, "utf8"));
  fs.writeFileSync(file, JSON.stringify({ ...rec, accepted_at: iso(86_400_000) }));
  const d = evaluateTrustConfig(v1, { stateDir });
  assert.equal(d.trusted, false);
  assert.ok(d.reasons.includes("trusted_time"));
});

test("trust config: root rotation needs a threshold of the current AND the new root; afterwards the old root alone fails", t => {
  const { roots, stateDir } = setup(t);
  const next = [canaryKey(), canaryKey(), canaryKey()];
  const rotateBody = configBody(next, { version: 2 });
  const onlyOld = evaluateTrustConfig(signTrustConfig(rotateBody, [roots[0].pem, roots[1].pem]), { stateDir });
  assert.deepEqual(onlyOld.reasons, ["new_root_threshold_met", "state_persisted"]);
  const onlyNew = evaluateTrustConfig(signTrustConfig(rotateBody, [next[0].pem, next[1].pem]), { stateDir });
  assert.deepEqual(onlyNew.reasons, ["root_threshold_met", "state_persisted"]);
  const both = evaluateTrustConfig(signTrustConfig(rotateBody, [roots[0].pem, roots[1].pem, next[1].pem, next[2].pem]), { stateDir });
  assert.equal(both.trusted, true, both.reasons.join());
  // Old root keys (e.g. retired after a suspected compromise) can no longer sign.
  const oldRootV3 = evaluateTrustConfig(signTrustConfig(configBody(roots, { version: 3 }), [roots[0].pem, roots[1].pem, roots[2].pem]), { stateDir });
  assert.equal(oldRootV3.trusted, false);
  assert.ok(oldRootV3.reasons.includes("root_threshold_met"));
  assert.equal(evaluateTrustConfig(signTrustConfig(configBody(next, { version: 3 }), [next[0].pem, next[2].pem]), { stateDir }).trusted, true);
});

test("trust config: signing-key rotation and sticky revocation (a revoked key cannot be re-trusted later)", t => {
  const { roots, stateDir } = setup(t);
  const oldKey = canaryKey(); const newKey = canaryKey();
  const s = o => signTrustConfig(configBody(roots, o), [roots[0].pem, roots[1].pem]);
  const v1 = evaluateTrustConfig(s({ version: 1, trusted_keys: [{ keyid: oldKey.sha256, roles: ["capability-issuer"] }] }), { stateDir });
  assert.equal(trustConfigTrustsKey(v1, oldKey.sha256, "capability-issuer"), true);
  const v2 = evaluateTrustConfig(s({ version: 2, trusted_keys: [{ keyid: newKey.sha256, roles: ["capability-issuer"] }], revoked_keys: [oldKey.sha256] }), { stateDir });
  assert.equal(trustConfigTrustsKey(v2, oldKey.sha256, "capability-issuer"), false);
  assert.equal(trustConfigTrustsKey(v2, newKey.sha256, "capability-issuer"), true);
  // v3 tries to list the revoked key again and drops it from revoked_keys.
  const v3 = evaluateTrustConfig(s({ version: 3, trusted_keys: [{ keyid: oldKey.sha256, roles: ["capability-issuer"] }] }), { stateDir });
  assert.equal(v3.trusted, true);
  assert.equal(trustConfigTrustsKey(v3, oldKey.sha256, "capability-issuer"), false, "revocations persist across versions");
  assert.ok(v3.effective.revoked_keys.includes(oldKey.sha256));
});

test("trust config: unenrolled, corrupted or unexpected state fails closed; malformed bodies are refused", t => {
  const { roots, stateDir } = setup(t);
  const env = signTrustConfig(configBody(roots), [roots[0].pem, roots[1].pem]);
  assert.deepEqual(evaluateTrustConfig(env, { stateDir: path.join(stateDir, "missing") }).reasons[0], "anchor_present");
  assert.equal(evaluateTrustConfigAll(env, { stateDirs: [] }).trusted, false);
  fs.writeFileSync(path.join(stateDir, "versions", "v000000000009.json"), "{not json");
  assert.ok(evaluateTrustConfig(env, { stateDir }).reasons.includes("state_readable"));
  fs.rmSync(path.join(stateDir, "versions", "v000000000009.json"));
  fs.writeFileSync(path.join(stateDir, "versions", "notes.txt"), "x");
  assert.ok(evaluateTrustConfig(env, { stateDir }).reasons.includes("state_readable"));
  fs.rmSync(path.join(stateDir, "versions", "notes.txt"));
  assert.throws(() => initTrustState(stateDir, { threshold: 2, rootKeyids: roots.map(r => r.sha256) }), /AML_TRUST_ANCHOR_EXISTS/);
  assert.equal(validateTrustConfigBody({ ...env.signed, extra: true }), "body_fields");
  assert.equal(validateTrustConfigBody({ ...env.signed, root: { threshold: 4, keyids: env.signed.root.keyids } }), "root");
  assert.equal(validateTrustConfigBody({ ...env.signed, trusted_keys: [{ keyid: roots[0].sha256, roles: ["root"] }] }), "trusted_key_roles");
  assert.equal(validateTrustConfigBody({ ...env.signed, version: 0 }), "version");
  assert.throws(() => signTrustConfig({ ...env.signed, version: 1.5 }, [roots[0].pem]), /VERSION/);
});

test("trust config: decisions cannot be forged or mutated into trust", t => {
  const { roots, stateDir } = setup(t);
  const key = canaryKey();
  const denied = evaluateTrustConfig(signTrustConfig(configBody(roots, { trusted_keys: [{ keyid: key.sha256, roles: ["receipt"] }] }), [roots[0].pem]), { stateDir });
  assert.equal(denied.trusted, false);
  assert.throws(() => { "use strict"; denied.trusted = true; }, TypeError);
  assert.throws(() => { denied.reasons.length = 0; }, TypeError);
  const lookAlike = JSON.parse(JSON.stringify({ trusted: true, reasons: [], expires_at: iso(60_000),
    effective: { trusted_keys: [{ keyid: key.sha256, roles: ["receipt"] }], revoked_keys: [], require_single_use: false, policy_sha256: sha("p") } }));
  assert.equal(trustConfigTrustsKey(lookAlike, key.sha256, "receipt"), false);
  assert.equal(trustConfigPinMatches(lookAlike, "policy_sha256", sha("p")), false);
  assert.equal(trustConfigRequiresSingleUse(lookAlike), true, "fail closed: a look-alike is treated as requiring single use");
});

test("trust config: digest pins come only from a trusted config; a null digest pins nothing", t => {
  const { roots, stateDir } = setup(t);
  const d = evaluateTrustConfig(signTrustConfig(configBody(roots, { registry_sha256: sha("registry-v2") }), [roots[0].pem, roots[1].pem]), { stateDir });
  assert.equal(trustConfigPinMatches(d, "registry_sha256", sha("registry-v2")), true);
  assert.equal(trustConfigPinMatches(d, "registry_sha256", sha("registry-v1")), false);
  assert.equal(trustConfigPinMatches(d, "policy_sha256", null), false);
  assert.equal(trustConfigPinMatches(d, "trusted_keys", sha("x")), false);
});

test("trust config: enrollment is additive; the system directory is always consulted", t => {
  const { stateDir } = setup(t);
  const other = tempDir(t);
  assert.deepEqual(enrolledTrustStateDirs([stateDir], { systemDir: other }), [path.resolve(stateDir)]);
  assert.deepEqual(enrolledTrustStateDirs([other], { systemDir: stateDir }), [path.resolve(stateDir)], "an env/flag dir cannot replace an enrolled system dir");
  assert.deepEqual(enrolledTrustStateDirs([null, ""], { systemDir: other }), []);
});

test("trust config: concurrent acceptance of v2 and v3 by separate processes never leaves v2 as the latest", async t => {
  const { roots, stateDir } = setup(t);
  const dir = tempDir(t);
  const files = [2, 3].map(v => {
    const file = path.join(dir, `v${v}.json`);
    fs.writeFileSync(file, JSON.stringify(signTrustConfig(configBody(roots, { version: v }), [roots[0].pem, roots[1].pem])));
    return file;
  });
  const script = `import fs from "node:fs"; import { evaluateTrustConfig } from ${JSON.stringify(path.resolve("runtime/trustConfig.js"))};
    const start = Number(process.argv[2]); while (Date.now() < start) {}
    const d = evaluateTrustConfig(JSON.parse(fs.readFileSync(process.argv[1], "utf8")), { stateDir: process.argv[3] });
    process.stdout.write(JSON.stringify({ trusted: d.trusted, version: d.version, reasons: d.reasons }));`;
  for (let round = 0; round < 3; round += 1) {
    const start = Date.now() + 300;
    const runs = await Promise.all(files.map(file => new Promise(resolve => {
      const child = spawn(process.execPath, ["--input-type=module", "-e", script, file, String(start), stateDir]);
      let out = ""; child.stdout.on("data", c => { out += c; });
      let err = ""; child.stderr.on("data", c => { err += c; });
      child.on("close", () => { try { resolve(JSON.parse(out)); } catch { resolve({ error: err || out }); } });
    })));
    assert.equal(readTrustState(stateDir).latest.version, 3);
    assert.equal(runs.find(r => r.version === 3).trusted, true);
  }
  const late = evaluateTrustConfig(JSON.parse(fs.readFileSync(files[0], "utf8")), { stateDir });
  assert.equal(late.trusted, false);
  assert.ok(late.reasons.includes("not_rolled_back"));
});
