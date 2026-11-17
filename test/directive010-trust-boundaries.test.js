// Directive 010 trust boundaries. Three separate questions:
//   signature validity  - the bytes were signed by the key in the evidence;
//   trustworthy identity - that key is the one the relying party pinned;
//   authorized action    - this executor, in this session, for this intent,
//                          not yet consumed, not expired by the local clock.
// Tests named "LIMIT:" assert behaviour that is NOT prevented and is
// documented as residual risk (stolen pinned key, compromised host,
// stateless verifier replay); they fail if that limit silently changes.
// They describe the explicit-pin path, which is unchanged when no trust
// config is enrolled. The opt-in mitigations (signed trust config with
// revocation and rollback protection, durable single-use store) are tested in
// test/trust-config*.test.js and test/durable-consumption.test.js.
import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import {
  signCapabilityToken, verifyCapabilityToken, authorizeCapabilityToken, createCapabilityConsumptionGuard,
  executeAccountableIntent, signExecutionReceipt
} from "../index.js";

function keyPair() {
  const { privateKey, publicKey } = crypto.generateKeyPairSync("ed25519");
  return { pem: privateKey.export({ type: "pkcs8", format: "pem" }).toString(),
    sha256: crypto.createHash("sha256").update(publicKey.export({ type: "spki", format: "der" })).digest("hex") };
}
const sha = s => crypto.createHash("sha256").update(s).digest("hex");
const INTENT = sha("deploy service-a@1.2.3 to prod");
const OTHER_INTENT = sha("delete database prod");
const iso = ms => new Date(Date.now() + ms).toISOString();

function mint(key, overrides = {}) {
  return signCapabilityToken({ issuer: "relying-party-ca", subject: "executor-a", audience: "deployer",
    capabilities: ["deploy"], issued_at: iso(-60_000), expires_at: iso(600_000), nonce: crypto.randomUUID(),
    session_id: "session-1", intent_sha256: INTENT, ...overrides }, key.pem);
}
function expect(key) {
  return { trustedIssuerKeySha256: key.sha256, audience: "deployer", subject: "executor-a", sessionId: "session-1",
    intentSha256: INTENT, requiredCapability: "deploy", consumptionGuard: createCapabilityConsumptionGuard() };
}

test("capability token: a valid self-signed token is not a trusted identity and not an authorization", () => {
  const issuer = keyPair(); const attacker = keyPair();
  const forged = mint(attacker, { capabilities: ["deploy", "admin"] });
  assert.equal(verifyCapabilityToken(forged, { requiredCapability: "admin" }).valid, true, "signature validity alone");
  const decision = authorizeCapabilityToken(forged, expect(issuer));
  assert.equal(decision.valid, true);
  assert.equal(decision.authorized, false);
  assert.deepEqual(decision.reasons, ["issuer_key_pinned"]);
  // Positive control: same claims from the pinned issuer key authorize.
  const ok = authorizeCapabilityToken(mint(issuer), expect(issuer));
  assert.equal(ok.authorized, true, ok.reasons.join());
  assert.deepEqual(ok.reasons, []);
  // No pin at all, or a malformed pin, never authorizes.
  assert.equal(authorizeCapabilityToken(mint(issuer), { ...expect(issuer), trustedIssuerKeySha256: null }).authorized, false);
  assert.equal(authorizeCapabilityToken(mint(issuer), { ...expect(issuer), trustedIssuerKeySha256: issuer.sha256.toUpperCase() }).authorized, false);
});

test("capability token: substituted key material inside the token is rejected even when the fingerprint field is pinned", () => {
  const issuer = keyPair(); const attacker = keyPair();
  const token = mint(attacker);
  // Attacker copies the pinned fingerprint into the token but keeps its own key.
  const swapped = { ...token, public_key_fingerprint: issuer.sha256 };
  const d = authorizeCapabilityToken(swapped, expect(issuer));
  assert.equal(d.valid, false);
  assert.equal(d.authorized, false);
  assert.ok(d.reasons.includes("signature_valid") && d.reasons.includes("issuer_key_pinned"));
});

test("capability token: evidence does not transfer between sessions, executors, audiences or intents", () => {
  const issuer = keyPair();
  const token = mint(issuer);
  const cases = {
    session_bound: { sessionId: "session-2" },
    executor_bound: { subject: "executor-b" },
    audience_bound: { audience: "billing" },
    intent_bound: { intentSha256: OTHER_INTENT },
    capability_granted: { requiredCapability: "admin" }
  };
  for (const [reason, change] of Object.entries(cases)) {
    const d = authorizeCapabilityToken(token, { ...expect(issuer), ...change });
    assert.equal(d.authorized, false, reason);
    assert.deepEqual(d.reasons, [reason], reason);
  }
  // A relying party that does not state what it expects gets no authorization.
  for (const missing of ["audience", "subject", "sessionId", "intentSha256", "requiredCapability"]) {
    assert.equal(authorizeCapabilityToken(token, { ...expect(issuer), [missing]: null }).authorized, false, missing);
  }
  // Tokens minted without session/intent bindings (pre-Directive 010) cannot authorize.
  const legacy = signCapabilityToken({ issuer: "x", subject: "executor-a", audience: "deployer", capabilities: ["deploy"],
    expires_at: iso(600_000), nonce: "n1" }, issuer.pem);
  assert.equal(verifyCapabilityToken(legacy).valid, true);
  assert.deepEqual(authorizeCapabilityToken(legacy, expect(issuer)).reasons, ["session_bound", "intent_bound"]);
});

test("capability token: the bindings are signed, so editing them breaks the signature", () => {
  const issuer = keyPair();
  const token = mint(issuer);
  const moved = { ...token, session_id: "session-2" };
  const d = authorizeCapabilityToken(moved, { ...expect(issuer), sessionId: "session-2" });
  assert.equal(d.authorized, false);
  assert.ok(d.reasons.includes("signature_valid"));
});

test("capability token: duplicate execution is refused once the nonce is consumed", () => {
  const issuer = keyPair();
  const token = mint(issuer);
  const first = authorizeCapabilityToken(token, expect(issuer));
  assert.equal(first.authorized, true);
  const second = authorizeCapabilityToken(token, { ...expect(issuer), consumptionGuard: first.consumptionGuard });
  assert.equal(second.authorized, false);
  assert.deepEqual(second.reasons, ["not_replayed"]);
  // Without a consumption guard there is no authorization at all (fail closed).
  assert.deepEqual(authorizeCapabilityToken(token, { ...expect(issuer), consumptionGuard: null }).reasons, ["not_replayed"]);
  // A token without a nonce can never be authorized.
  const noNonce = mint(issuer, { nonce: null });
  assert.ok(authorizeCapabilityToken(noNonce, expect(issuer)).reasons.includes("nonce_present"));
});

test("capability token: expiry uses only the local clock; a caller cannot supply a time", () => {
  const issuer = keyPair();
  const expired = mint(issuer, { issued_at: iso(-120_000), expires_at: iso(-1_000) });
  // A caller-supplied `now` (or `clock`) option is ignored, not honoured.
  const d = authorizeCapabilityToken(expired, { ...expect(issuer), now: iso(-60_000), clock: () => Date.now() - 60_000 });
  assert.equal(d.authorized, false);
  assert.deepEqual(d.reasons, ["not_expired"]);
  const future = mint(issuer, { issued_at: iso(120_000), expires_at: iso(600_000) });
  assert.deepEqual(authorizeCapabilityToken(future, expect(issuer)).reasons, ["not_expired"]);
  const noExpiry = mint(issuer, { expires_at: null });
  assert.deepEqual(authorizeCapabilityToken(noExpiry, expect(issuer)).reasons, ["not_expired"]);
});

test("LIMIT: a stolen pinned issuer key mints tokens that authorize (residual; needs key rotation/revocation outside this check)", () => {
  const issuer = keyPair();
  const stolen = { ...issuer }; // the attacker holds the same private key
  const d = authorizeCapabilityToken(mint(stolen, { subject: "executor-a", capabilities: ["deploy"] }), expect(issuer));
  assert.equal(d.authorized, true, "signature cryptography cannot distinguish a thief from the key owner");
});

test("LIMIT: a consumption guard is only as durable as its storage; a reset guard re-admits the token", () => {
  const issuer = keyPair();
  const token = mint(issuer);
  assert.equal(authorizeCapabilityToken(token, expect(issuer)).authorized, true);
  assert.equal(authorizeCapabilityToken(token, expect(issuer)).authorized, true, "fresh guard: replay not detected");
});

function cli(args, env = {}) {
  const out = spawnSync(process.execPath, args, { encoding: "utf8", env: { ...process.env, ...env } });
  let json = null; try { json = JSON.parse(out.stdout); } catch { /* text */ }
  return { status: out.status, json };
}

test("LIMIT: verifier CLIs are stateless; the same pinned receipt verifies (exit 0) on every replay", t => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "aml-d010-tb-"));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const owner = keyPair();
  const receipt = executeAccountableIntent({ transmission: "tb", nodes: [{ type: "engram", identifier: "c",
    properties: { purpose: "p", attention_cost: 1, restoration_value: 5 } }] }, { timestamp: "2030-01-01T00:00:00.000Z" });
  const file = path.join(dir, "signed.json");
  fs.writeFileSync(file, JSON.stringify(signExecutionReceipt(receipt, owner.pem)));
  const a = cli(["bin/aml.js", "verify-signed-receipt", file, "--trusted-key-sha256", owner.sha256]);
  const b = cli(["bin/aml.js", "verify-signed-receipt", file, "--trusted-key-sha256", owner.sha256]);
  assert.equal(a.status, 0); assert.equal(b.status, 0);
  // Single-use enforcement belongs to the executor (authorizeCapabilityToken + a durable guard).
});

test("LIMIT: a compromised host controls environment pins; pinning the attacker key authorizes the attacker proof", t => {
  // The relying party's pin is only as trustworthy as the host that holds it.
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "aml-d010-tb-"));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const attacker = keyPair();
  const owner = keyPair();
  const file = path.join(dir, "signed.json");
  const receipt = executeAccountableIntent({ transmission: "tb2", nodes: [{ type: "engram", identifier: "c",
    properties: { purpose: "p", attention_cost: 1, restoration_value: 5 } }] }, { timestamp: "2030-01-01T00:00:00.000Z" });
  fs.writeFileSync(file, JSON.stringify(signExecutionReceipt(receipt, attacker.pem)));
  assert.equal(cli(["bin/aml.js", "verify-signed-receipt", file, "--trusted-key-sha256", owner.sha256]).status, 3);
  assert.equal(cli(["bin/aml.js", "verify-signed-receipt", file, "--trusted-key-sha256", attacker.sha256]).status, 0,
    "a host that can rewrite the pin can authorize anything; pins must come from outside the compromised host");
});
