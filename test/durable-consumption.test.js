// Durable single-use store for capability tokens: atomic consume across
// processes, restart, executors sharing a store, crash between consume and
// action, and integration with the signed trust config. Synthetic keys only.
import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { spawn, spawnSync } from "node:child_process";
import { signCapabilityToken, authorizeCapabilityToken, createCapabilityConsumptionGuard } from "../runtime/capabilityToken.js";
import { openDurableConsumptionStore, isDurableConsumptionStore, consumptionKey, DURABLE_CONSUMPTION_STORE_TYPE } from "../runtime/consumptionStore.js";
import { signTrustConfig, evaluateTrustConfig, initTrustState } from "../runtime/trustConfig.js";
import { canaryKey, configBody, iso, sha, tempDir } from "./fixtures/trust-config/helpers.mjs";

const CHILD = path.resolve("test/fixtures/trust-config/consume-child.mjs");
const INTENT = sha("deploy service-a@1.2.3 to prod");

function mint(key, overrides = {}) {
  return signCapabilityToken({ issuer: "relying-party-ca", subject: "executor-a", audience: "deployer",
    capabilities: ["deploy"], issued_at: iso(-60_000), expires_at: iso(600_000), nonce: crypto.randomUUID(),
    session_id: "session-1", intent_sha256: INTENT, ...overrides }, key.pem);
}
const expect = (key, extra = {}) => ({ trustedIssuerKeySha256: key.sha256, audience: "deployer", subject: "executor-a",
  sessionId: "session-1", intentSha256: INTENT, requiredCapability: "deploy", ...extra });

function runChild(job, dir, { wait = true } = {}) {
  const jobFile = path.join(dir, `job-${crypto.randomUUID()}.json`);
  fs.writeFileSync(jobFile, JSON.stringify(job));
  const env = { ...process.env, AML_TC_CHILD: "1", AML_TC_JOB: jobFile };
  if (wait) {
    const out = spawnSync(process.execPath, [CHILD], { encoding: "utf8", env });
    assert.equal(out.status, 0, out.stderr);
    return JSON.parse(out.stdout);
  }
  return spawn(process.execPath, [CHILD], { env });
}
const collect = child => new Promise(resolve => {
  let out = ""; child.stdout.on("data", c => { out += c; });
  child.on("close", () => resolve(JSON.parse(out)));
});

test("durable store: consume is exactly-once per key and survives reopening", t => {
  const dir = tempDir(t);
  const key = consumptionKey(["capability-token", "a", "b"]);
  assert.equal(openDurableConsumptionStore(dir).consume(key), true);
  assert.equal(openDurableConsumptionStore(dir).consume(key), false);
  assert.equal(openDurableConsumptionStore(dir).has(key), true);
  assert.throws(() => openDurableConsumptionStore(dir).consume("../../etc/passwd"), /KEY_INVALID/);
  assert.throws(() => consumptionKey(["a\u0000b"]), /KEY_INVALID/);
  assert.notEqual(consumptionKey(["ab", "c"]), consumptionKey(["a", "bc"]));
});

test("durable store: a look-alike store object is not a durable store", t => {
  const fake = { type: DURABLE_CONSUMPTION_STORE_TYPE, consume: () => true };
  assert.equal(isDurableConsumptionStore(fake), false);
  const issuer = canaryKey();
  const d = authorizeCapabilityToken(mint(issuer), expect(issuer, { consumptionStore: fake }));
  assert.equal(d.authorized, false);
  assert.deepEqual(d.reasons, ["not_replayed"]);
  assert.equal(isDurableConsumptionStore(openDurableConsumptionStore(tempDir(t))), true);
});

test("capability token + durable store: replay across process restarts is refused", t => {
  const dir = tempDir(t);
  const storeDir = path.join(dir, "store");
  const issuer = canaryKey();
  const token = mint(issuer);
  const first = runChild({ token, expect: expect(issuer), storeDir }, dir);
  assert.equal(first.authorized, true, first.reasons.join());
  assert.equal(first.replay_protection, "durable");
  const second = runChild({ token, expect: expect(issuer), storeDir }, dir);
  assert.equal(second.authorized, false);
  assert.deepEqual(second.reasons, ["not_replayed"]);
  // Control: without the durable store (fresh in-memory guard per process) the replay is admitted.
  assert.equal(runChild({ token, expect: expect(issuer) }, dir).authorized, true);
});

test("capability token + durable store: N concurrent processes, exactly one authorizes", async t => {
  const dir = tempDir(t);
  const storeDir = path.join(dir, "store");
  const issuer = canaryKey();
  const token = mint(issuer);
  const startAt = Date.now() + 400;
  const results = await Promise.all(Array.from({ length: 8 }, () => collect(runChild({ token, expect: expect(issuer), storeDir, startAt }, dir, { wait: false }))));
  assert.equal(results.filter(r => r.authorized === true).length, 1, JSON.stringify(results));
});

test("capability token + durable store: replay by another executor or session sharing the store is refused", t => {
  const dir = tempDir(t);
  const store = openDurableConsumptionStore(path.join(dir, "store"));
  const issuer = canaryKey();
  const nonce = crypto.randomUUID();
  const forA = mint(issuer, { nonce });
  assert.equal(authorizeCapabilityToken(forA, expect(issuer, { consumptionStore: store })).authorized, true);
  // Same issuer + nonce re-minted for executor-b / session-2: the nonce is already consumed.
  const forB = mint(issuer, { nonce, subject: "executor-b", session_id: "session-2" });
  const d = authorizeCapabilityToken(forB, expect(issuer, { subject: "executor-b", sessionId: "session-2", consumptionStore: store }));
  assert.equal(d.authorized, false);
  assert.deepEqual(d.reasons, ["not_replayed"]);
  // Executor B presenting A's token fails on the executor binding and does not burn anything.
  const fresh = mint(issuer);
  const wrong = authorizeCapabilityToken(fresh, expect(issuer, { subject: "executor-b", consumptionStore: store }));
  assert.deepEqual(wrong.reasons, ["executor_bound", "not_replayed"]);
  assert.equal(authorizeCapabilityToken(fresh, expect(issuer, { consumptionStore: store })).authorized, true, "denied attempts do not consume");
});

test("capability token + durable store: crash after consume and before the action leaves the token burned (at-most-once)", async t => {
  const dir = tempDir(t);
  const storeDir = path.join(dir, "store");
  const actionLog = path.join(dir, "actions.log");
  const issuer = canaryKey();
  const token = mint(issuer);
  const child = runChild({ token, expect: expect(issuer), storeDir, actionLog, hangBeforeAction: true }, dir, { wait: false });
  await new Promise((resolve, reject) => {
    child.stdout.on("data", c => { if (String(c).includes("CONSUMED")) { child.kill("SIGKILL"); resolve(); } });
    child.on("close", code => code !== null && reject(new Error(`child exited ${code} before consuming`)));
  });
  await new Promise(resolve => child.on("close", resolve));
  assert.equal(fs.existsSync(actionLog), false, "the action never ran");
  const retry = runChild({ token, expect: expect(issuer), storeDir, actionLog }, dir);
  assert.equal(retry.authorized, false, "restart after the crash cannot re-run the authorization");
  assert.equal(fs.existsSync(actionLog), false);
});

test("capability token + durable store: random SIGKILLs never produce more than one action per token", async t => {
  const dir = tempDir(t);
  const storeDir = path.join(dir, "store");
  const actionLog = path.join(dir, "actions.log");
  const issuer = canaryKey();
  const tokens = Array.from({ length: 6 }, () => mint(issuer));
  for (const [i, token] of tokens.entries()) {
    const attempts = Array.from({ length: 3 }, () => runChild({ token, expect: expect(issuer), storeDir, actionLog }, dir, { wait: false }));
    setTimeout(() => attempts[i % 3].kill("SIGKILL"), 5 + i * 7);
    await Promise.all(attempts.map(c => new Promise(resolve => c.on("close", resolve))));
  }
  const actions = fs.existsSync(actionLog) ? fs.readFileSync(actionLog, "utf8").trim().split("\n").filter(Boolean) : [];
  for (const token of tokens) assert.ok(actions.filter(n => n === token.nonce).length <= 1, token.nonce);
  // Every token that acted is consumed; a final retry of every token is refused.
  const store = openDurableConsumptionStore(storeDir);
  for (const token of tokens) {
    if (actions.includes(token.nonce)) assert.equal(store.has(consumptionKey(["capability-token", token.public_key_fingerprint, token.nonce])), true);
    if (store.has(consumptionKey(["capability-token", token.public_key_fingerprint, token.nonce]))) {
      assert.equal(authorizeCapabilityToken(token, expect(issuer, { consumptionStore: store })).authorized, false);
    }
  }
});

test("durable store: a partial record left by a crash during the write still counts as consumed (fail closed)", t => {
  const dir = tempDir(t);
  const store = openDurableConsumptionStore(dir);
  const issuer = canaryKey();
  const token = mint(issuer);
  const key = consumptionKey(["capability-token", token.public_key_fingerprint, token.nonce]);
  fs.writeFileSync(path.join(dir, "consumed", `${key}.json`), ""); // exclusive create happened, write did not
  const d = authorizeCapabilityToken(token, expect(issuer, { consumptionStore: store }));
  assert.equal(d.authorized, false);
  assert.deepEqual(d.reasons, ["not_replayed"]);
});

test("durable store: an I/O failure denies (read-only store directory)", t => {
  if (process.getuid?.() === 0) { t.skip("root bypasses directory permissions"); return; }
  const dir = tempDir(t);
  const store = openDurableConsumptionStore(dir);
  fs.chmodSync(path.join(dir, "consumed"), 0o500);
  t.after(() => { try { fs.chmodSync(path.join(dir, "consumed"), 0o700); } catch { /* already removed */ } });
  const issuer = canaryKey();
  assert.deepEqual(authorizeCapabilityToken(mint(issuer), expect(issuer, { consumptionStore: store })).reasons, ["not_replayed"]);
});

function trustSetup(t, overrides) {
  const roots = [canaryKey(), canaryKey(), canaryKey()];
  const stateDir = path.join(tempDir(t), "state");
  initTrustState(stateDir, { threshold: 2, rootKeyids: roots.map(r => r.sha256) });
  const decide = o => evaluateTrustConfig(signTrustConfig(configBody(roots, o), [roots[0].pem, roots[1].pem]), { stateDir });
  return { decide, first: decide(overrides) };
}

test("capability token + trust config: issuer must be trusted for capability-issuer; revocation stops a stolen key", t => {
  const issuer = canaryKey(); const other = canaryKey();
  const { decide, first } = trustSetup(t, { version: 1, trusted_keys: [{ keyid: issuer.sha256, roles: ["capability-issuer"] }, { keyid: other.sha256, roles: ["receipt"] }] });
  assert.equal(first.trusted, true, first.reasons.join());
  const base = { audience: "deployer", subject: "executor-a", sessionId: "session-1", intentSha256: INTENT, requiredCapability: "deploy" };
  const guard = () => createCapabilityConsumptionGuard();
  assert.equal(authorizeCapabilityToken(mint(issuer), { ...base, trustConfig: first, consumptionGuard: guard() }).authorized, true);
  assert.deepEqual(authorizeCapabilityToken(mint(other), { ...base, trustConfig: first, consumptionGuard: guard() }).reasons, ["issuer_key_pinned"], "wrong role");
  // Both a pin and a config: both must agree (AND).
  assert.deepEqual(authorizeCapabilityToken(mint(issuer), { ...base, trustConfig: first, trustedIssuerKeySha256: other.sha256, consumptionGuard: guard() }).reasons, ["issuer_key_pinned"]);
  // The key is reported stolen: v2 revokes it. Tokens it mints no longer authorize.
  const v2 = decide({ version: 2, trusted_keys: [], revoked_keys: [issuer.sha256] });
  assert.equal(v2.trusted, true);
  assert.deepEqual(authorizeCapabilityToken(mint(issuer), { ...base, trustConfig: v2, consumptionGuard: guard() }).reasons, ["issuer_key_pinned"]);
  // An untrusted config decision never authorizes.
  const rolledBack = decide({ version: 1, trusted_keys: [{ keyid: issuer.sha256, roles: ["capability-issuer"] }] });
  assert.equal(rolledBack.trusted, false);
  // (An untrusted config is also treated as requiring durable single use: fail closed.)
  assert.deepEqual(authorizeCapabilityToken(mint(issuer), { ...base, trustConfig: rolledBack, consumptionGuard: guard() }).reasons, ["issuer_key_pinned", "not_replayed"]);
});

test("capability token + trust config: require_single_use makes the durable store mandatory", t => {
  const issuer = canaryKey();
  const { first } = trustSetup(t, { require_single_use: true, trusted_keys: [{ keyid: issuer.sha256, roles: ["capability-issuer"] }] });
  const base = { audience: "deployer", subject: "executor-a", sessionId: "session-1", intentSha256: INTENT, requiredCapability: "deploy", trustConfig: first };
  assert.deepEqual(authorizeCapabilityToken(mint(issuer), { ...base, consumptionGuard: createCapabilityConsumptionGuard() }).reasons, ["not_replayed"]);
  const store = openDurableConsumptionStore(tempDir(t));
  const token = mint(issuer);
  const ok = authorizeCapabilityToken(token, { ...base, consumptionStore: store });
  assert.equal(ok.authorized, true, ok.reasons.join());
  assert.equal(ok.replay_protection, "durable");
  assert.equal(authorizeCapabilityToken(token, { ...base, consumptionStore: store }).authorized, false);
});
