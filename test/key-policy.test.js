// Ed25519-only rule for capability tokens and threshold authorizations
// (protocol/keyPolicy.js). Before this change an ECDSA P-256 or RSA key signed
// and verified both artifacts, and an ECDSA signature (r, s) had a second
// valid spelling (r, n - s). Now every non-Ed25519 key is refused explicitly,
// with or without a trust config, in JS, Python and Go (shared vectors in
// conformance/key-policy/). Synthetic canary keys only.
import test, { after } from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import {
  signCapabilityToken, verifyCapabilityToken, authorizeCapabilityToken, createCapabilityConsumptionGuard,
  createThresholdAuthorization, verifyThresholdAuthorization
} from "../index.js";
import { canonicalJSONStringify } from "../protocol/canonicalJson.js";
import { AML_KEY_TYPE_NOT_ED25519, isEd25519KeyObject, requireEd25519PrivateKey } from "../protocol/keyPolicy.js";
import { runVectors } from "../conformance/key-policy/run-js.mjs";

const VECTORS = "conformance/key-policy/vectors.json";
const hasGo = spawnSync("go", ["version"]).status === 0;
const FOREIGN = {
  "ecdsa-p256": () => crypto.generateKeyPairSync("ec", { namedCurve: "P-256" }),
  "ecdsa-p384": () => crypto.generateKeyPairSync("ec", { namedCurve: "P-384" }),
  "rsa-2048": () => crypto.generateKeyPairSync("rsa", { modulusLength: 2048 }),
  "rsa-pss-2048": () => crypto.generateKeyPairSync("rsa-pss", { modulusLength: 2048 }),
  ed448: () => crypto.generateKeyPairSync("ed448")
};
const pkcs8 = k => k.privateKey.export({ type: "pkcs8", format: "pem" }).toString();
const spki = k => k.publicKey.export({ type: "spki", format: "pem" }).toString();
const fpOf = k => crypto.createHash("sha256").update(k.publicKey.export({ type: "spki", format: "der" })).digest("hex");
const digestFor = k => (["ec", "rsa", "rsa-pss"].includes(k.privateKey.asymmetricKeyType) ? "sha256" : null);
const INTENT = "1".repeat(64);
const iso = ms => new Date(Date.now() + ms).toISOString();

// What a legacy producer (or attacker) can still hand a verifier: a fully
// bound token signed with a non-Ed25519 key, built without the AML signer.
function rawToken(k, over = {}) {
  const body = { type: "aml-capability-token/1", issuer: "synthetic-issuer", subject: "executor-a", audience: "deployer",
    capabilities: ["deploy"], issued_at: iso(-60_000), expires_at: iso(600_000), nonce: crypto.randomUUID(),
    session_id: "session-1", intent_sha256: INTENT, ...over };
  return { ...body, public_key_pem: spki(k), public_key_fingerprint: fpOf(k),
    signature_base64: crypto.sign(digestFor(k), Buffer.from(canonicalJSONStringify(body)), k.privateKey).toString("base64") };
}
const expectFor = k => ({ trustedIssuerKeySha256: fpOf(k), audience: "deployer", subject: "executor-a", sessionId: "session-1",
  intentSha256: INTENT, requiredCapability: "deploy", consumptionGuard: createCapabilityConsumptionGuard() });

test("signers refuse every non-Ed25519 private key with AML_KEY_TYPE_NOT_ED25519", () => {
  for (const [name, make] of Object.entries(FOREIGN)) {
    const k = make();
    assert.throws(() => signCapabilityToken({ issuer: "i", capabilities: ["x"], nonce: "n" }, pkcs8(k)),
      new RegExp(AML_KEY_TYPE_NOT_ED25519), `capability token ${name}`);
    assert.throws(() => createThresholdAuthorization({ a: 1 }, [pkcs8(k)], { threshold: 1 }),
      new RegExp(AML_KEY_TYPE_NOT_ED25519), `threshold ${name}`);
    assert.throws(() => requireEd25519PrivateKey(pkcs8(k)), new RegExp(AML_KEY_TYPE_NOT_ED25519));
    assert.equal(isEd25519KeyObject(k.publicKey), false);
  }
  const ed = crypto.generateKeyPairSync("ed25519");
  assert.equal(isEd25519KeyObject(requireEd25519PrivateKey(pkcs8(ed))), true);
  assert.equal(verifyCapabilityToken(signCapabilityToken({ issuer: "i", capabilities: ["x"], nonce: "n" }, pkcs8(ed))).valid, true);
});

test("a pinned, fully bound non-Ed25519 token never authorizes, even without a trust config", () => {
  for (const [name, make] of Object.entries(FOREIGN)) {
    const k = make();
    const token = rawToken(k);
    // The signature itself is cryptographically valid: refusal is the key type.
    const { public_key_pem: _p, public_key_fingerprint: _f, signature_base64, ...body } = token;
    assert.equal(crypto.verify(digestFor(k), Buffer.from(canonicalJSONStringify(body)), k.publicKey, Buffer.from(signature_base64, "base64")), true, name);
    assert.deepEqual(verifyCapabilityToken(token), { valid: false, reason: "key_type_not_ed25519" }, name);
    const d = authorizeCapabilityToken(token, expectFor(k));
    assert.equal(d.authorized, false, name);
    assert.equal(d.valid, false, name);
    assert.deepEqual(d.reasons, ["signature_valid", "issuer_key_pinned"], name);
    assert.equal(d.verification_reason, "key_type_not_ed25519", name);
  }
  // Positive control: the same binding with an Ed25519 issuer authorizes once.
  const ed = crypto.generateKeyPairSync("ed25519");
  const ok = authorizeCapabilityToken(rawToken(ed), expectFor(ed));
  assert.equal(ok.authorized, true, ok.reasons.join());
  assert.equal(ok.verification_reason, null);
});

test("ECDSA malleability: both spellings (r, s) and (r, n - s) of a P-256 token are refused", () => {
  const N = BigInt("0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551");
  const k = FOREIGN["ecdsa-p256"]();
  const token = rawToken(k);
  const sig = crypto.sign("sha256", Buffer.from("m"), { key: k.privateKey, dsaEncoding: "ieee-p1363" });
  const s = BigInt(`0x${sig.subarray(32).toString("hex")}`);
  const malleated = Buffer.concat([sig.subarray(0, 32), Buffer.from((N - s).toString(16).padStart(64, "0"), "hex")]);
  assert.equal(crypto.verify("sha256", Buffer.from("m"), { key: k.publicKey, dsaEncoding: "ieee-p1363" }, malleated), true,
    "baseline: the malleated ECDSA signature verifies at the crypto layer");
  const vectors = JSON.parse(fs.readFileSync(VECTORS, "utf8"));
  const high = vectors.cases.find(c => c.name === "token_ecdsa_p256_malleated_high_s_refused");
  const low = vectors.cases.find(c => c.name === "token_ecdsa-p256_signature_valid_but_refused");
  assert.notEqual(high.artifact.signature_base64, low.artifact.signature_base64);
  assert.deepEqual(verifyCapabilityToken(high.artifact), { valid: false, reason: "key_type_not_ed25519" });
  assert.deepEqual(verifyCapabilityToken(low.artifact), { valid: false, reason: "key_type_not_ed25519" });
  assert.deepEqual(verifyCapabilityToken(token), { valid: false, reason: "key_type_not_ed25519" });
});

test("threshold authorization: any non-Ed25519 signer refuses the whole artifact (no silent skip)", () => {
  const eds = [0, 1].map(() => crypto.generateKeyPairSync("ed25519"));
  const good = createThresholdAuthorization({ action: "x" }, eds.map(pkcs8), { threshold: 2 });
  assert.equal(verifyThresholdAuthorization(good).valid, true);
  for (const [name, make] of Object.entries(FOREIGN)) {
    const k = make();
    const message = Buffer.from(canonicalJSONStringify({ context: good.type, version: good.version, threshold: 2, payload: good.payload }));
    const extra = { key_fingerprint: fpOf(k), public_key_pem: spki(k), signature_base64: crypto.sign(digestFor(k), message, k.privateKey).toString("base64") };
    const mixed = { ...structuredClone(good), signatures: [...good.signatures, extra] };
    const r = verifyThresholdAuthorization(mixed);
    assert.equal(r.valid, false, name);
    assert.equal(r.reason, "key_type_not_ed25519", name);
    assert.equal(r.valid_signatures, 0, name);
    assert.deepEqual(r.rejected_key_types, [k.publicKey.asymmetricKeyType], name);
  }
});

test("key-policy vectors are current, denial-heavy, and hold no private key", () => {
  const check = spawnSync(process.execPath, ["conformance/key-policy/generate.mjs", "--check"], { encoding: "utf8" });
  assert.equal(check.status, 0, check.stderr);
  const text = fs.readFileSync(VECTORS, "utf8");
  assert.doesNotMatch(text, /PRIVATE KEY/);
  const vectors = JSON.parse(text);
  assert.ok(vectors.cases.filter(c => c.expect.reason === "key_type_not_ed25519").length >= 10);
  assert.ok(vectors.cases.filter(c => c.expect.valid === true).length >= 2, "positive controls present");
});

let goDir = null;
after(() => { if (goDir) fs.rmSync(goDir, { recursive: true, force: true }); });

test("JavaScript, Python and Go decide every key-policy vector identically", { timeout: 120_000 }, t => {
  const vectors = JSON.parse(fs.readFileSync(VECTORS, "utf8"));
  const js = JSON.parse(JSON.stringify(runVectors(vectors).results));
  vectors.cases.forEach((c, i) => assert.deepEqual(js[i].decision, c.expect, `js ${c.name}`));
  const py = spawnSync("python3", ["independent/python/key_policy.py", "conformance", VECTORS], { encoding: "utf8", env: { ...process.env, PYTHONDONTWRITEBYTECODE: "1" } });
  assert.equal(py.status, 0, py.stderr);
  assert.deepEqual(JSON.parse(py.stdout).results, js, "python equals javascript");
  if (!hasGo) { t.diagnostic("go toolchain not installed: Go key-policy conformance skipped"); return; }
  goDir = fs.mkdtempSync(path.join(os.tmpdir(), "aml-go-kp-"));
  const bin = path.join(goDir, "aml-go-witness");
  const built = spawnSync("go", ["build", "-o", bin, "."], { cwd: "independent/go", encoding: "utf8" });
  assert.equal(built.status, 0, built.stderr);
  const g = spawnSync(bin, ["key-policy-conformance", VECTORS], { encoding: "utf8" });
  assert.equal(g.status, 0, g.stderr);
  assert.deepEqual(JSON.parse(g.stdout).results, js, "go equals javascript");
});
