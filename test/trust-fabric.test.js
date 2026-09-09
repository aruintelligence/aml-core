import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import {
  canonicalJSONStringify,
  createTrustDelegation,
  createSignedTrustDelegation,
  verifyTrustDelegation,
  verifyDelegationChain,
  createTransparencyLog,
  appendTransparencyEntry,
  verifyTransparencyLog
} from "../index.js";

function keyPair() {
  const { privateKey, publicKey } = crypto.generateKeyPairSync("ed25519");
  const publicPem = publicKey.export({ type: "spki", format: "pem" }).toString();
  const fingerprint = crypto.createHash("sha256").update(publicKey.export({ type: "spki", format: "der" })).digest("hex");
  return {
    privatePem: privateKey.export({ type: "pkcs8", format: "pem" }).toString(),
    publicPem,
    fingerprint
  };
}

test("canonical JSON is stable across key order", () => {
  assert.equal(
    canonicalJSONStringify({ b: 2, a: { y: 2, x: 1 } }),
    canonicalJSONStringify({ a: { x: 1, y: 2 }, b: 2 })
  );
});

test("legacy trust delegation is explicitly integrity-only and cannot satisfy authority chain by default", () => {
  const first = createTrustDelegation({ issuer: "root", delegate: "team", capabilities: ["sign-policy", "sign-receipt"] });
  const second = createTrustDelegation({ issuer: "team", delegate: "agent", capabilities: ["sign-policy"] });

  const single = verifyTrustDelegation(first, { requiredCapability: "sign-policy" });
  assert.equal(single.valid, true);
  assert.equal(single.authority_authenticated, false);
  assert.equal(single.integrity_only, true);

  const authority = verifyDelegationChain([first, second], { rootIssuer: "root", requiredCapability: "sign-policy" });
  assert.equal(authority.valid, false);
  assert.equal(authority.reason, "root_key_required");

  const integrity = verifyDelegationChain([first, second], {
    rootIssuer: "root",
    requiredCapability: "sign-policy",
    integrityOnly: true
  });
  assert.equal(integrity.valid, true);
  assert.equal(integrity.authority_authenticated, false);
});

test("signed trust chain preserves cryptographic issuer and delegate key continuity", () => {
  const root = keyPair();
  const team = keyPair();
  const agent = keyPair();

  const first = createSignedTrustDelegation({
    issuer: "root",
    delegate: "team",
    delegate_public_key_pem: team.publicPem,
    capabilities: ["sign-policy", "sign-receipt"]
  }, root.privatePem);
  const second = createSignedTrustDelegation({
    issuer: "team",
    delegate: "agent",
    delegate_public_key_pem: agent.publicPem,
    capabilities: ["sign-policy"]
  }, team.privatePem);

  const result = verifyDelegationChain([first, second], {
    rootIssuer: "root",
    rootKeyFingerprint: root.fingerprint,
    requiredCapability: "sign-policy"
  });
  assert.equal(result.valid, true);
  assert.equal(result.authority_authenticated, true);
  assert.equal(result.leaf, "agent");
  assert.equal(result.leaf_key_fingerprint, agent.fingerprint);
});

test("self-signed forged root name cannot satisfy a pinned trust root", () => {
  const trustedRoot = keyPair();
  const attacker = keyPair();
  const delegate = keyPair();
  const forged = createSignedTrustDelegation({
    issuer: "root",
    delegate: "attacker-team",
    delegate_public_key_pem: delegate.publicPem,
    capabilities: ["sign-policy"]
  }, attacker.privatePem);

  const result = verifyDelegationChain([forged], {
    rootIssuer: "root",
    rootKeyFingerprint: trustedRoot.fingerprint,
    requiredCapability: "sign-policy"
  });
  assert.equal(result.valid, false);
  assert.equal(result.reason, "unexpected_root_key");
});

test("signed chain rejects broken delegate-to-issuer key continuity", () => {
  const root = keyPair();
  const delegatedTeam = keyPair();
  const impostorTeam = keyPair();
  const agent = keyPair();

  const first = createSignedTrustDelegation({
    issuer: "root",
    delegate: "team",
    delegate_public_key_pem: delegatedTeam.publicPem,
    capabilities: ["sign-policy"]
  }, root.privatePem);
  const second = createSignedTrustDelegation({
    issuer: "team",
    delegate: "agent",
    delegate_public_key_pem: agent.publicPem,
    capabilities: ["sign-policy"]
  }, impostorTeam.privatePem);

  const result = verifyDelegationChain([first, second], {
    rootIssuer: "root",
    rootKeyFingerprint: root.fingerprint,
    requiredCapability: "sign-policy"
  });
  assert.equal(result.valid, false);
  assert.equal(result.reason, "broken_key_continuity");
  assert.equal(result.index, 1);
});

test("trust delegation mutation is detected", () => {
  const delegation = createTrustDelegation({ issuer: "root", delegate: "team", capabilities: ["sign-policy"] });
  const mutated = structuredClone(delegation);
  mutated.capabilities.push("admin");
  assert.equal(verifyTrustDelegation(mutated).valid, false);
});

test("signed trust delegation rejects invalid time fields instead of bypassing expiry checks", () => {
  const root = keyPair();
  const team = keyPair();
  const delegation = createSignedTrustDelegation({
    issuer: "root",
    delegate: "team",
    delegate_public_key_pem: team.publicPem,
    capabilities: ["sign-policy"],
    expires_at: "not-a-date"
  }, root.privatePem);

  const result = verifyTrustDelegation(delegation, { now: "2030-01-01T00:00:00.000Z" });
  assert.equal(result.valid, false);
  assert.equal(result.reason, "invalid_expiry");
});

test("transparency log is append-only and tamper evident", () => {
  let log = createTransparencyLog();
  log = appendTransparencyEntry(log, { receipt: "r1" }, { timestamp: "2026-01-01T00:00:00.000Z" });
  log = appendTransparencyEntry(log, { receipt: "r2" }, { timestamp: "2026-01-01T00:01:00.000Z" });
  assert.equal(verifyTransparencyLog(log).valid, true);

  const mutated = structuredClone(log);
  mutated.entries[0].payload_hash = "0".repeat(64);
  assert.equal(verifyTransparencyLog(mutated).valid, false);
});
