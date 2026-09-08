import test from "node:test";
import assert from "node:assert/strict";
import {
  canonicalJSONStringify,
  createTrustDelegation,
  verifyTrustDelegation,
  verifyDelegationChain,
  createTransparencyLog,
  appendTransparencyEntry,
  verifyTransparencyLog
} from "../index.js";

test("canonical JSON is stable across key order", () => {
  assert.equal(
    canonicalJSONStringify({ b: 2, a: { y: 2, x: 1 } }),
    canonicalJSONStringify({ a: { x: 1, y: 2 }, b: 2 })
  );
});

test("trust delegations verify and chains preserve authority continuity", () => {
  const first = createTrustDelegation({ issuer: "root", delegate: "team", capabilities: ["sign-policy", "sign-receipt"] });
  const second = createTrustDelegation({ issuer: "team", delegate: "agent", capabilities: ["sign-policy"] });

  assert.equal(verifyTrustDelegation(first, { requiredCapability: "sign-policy" }).valid, true);
  assert.equal(verifyDelegationChain([first, second], { rootIssuer: "root", requiredCapability: "sign-policy" }).valid, true);

  const broken = structuredClone(second);
  broken.issuer = "attacker";
  assert.equal(verifyDelegationChain([first, broken], { rootIssuer: "root", requiredCapability: "sign-policy" }).valid, false);
});

test("trust delegation mutation is detected", () => {
  const delegation = createTrustDelegation({ issuer: "root", delegate: "team", capabilities: ["sign-policy"] });
  const mutated = structuredClone(delegation);
  mutated.capabilities.push("admin");
  assert.equal(verifyTrustDelegation(mutated).valid, false);
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
