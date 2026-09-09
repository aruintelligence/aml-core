import test from "node:test";
import assert from "node:assert/strict";
import { createRevocationRegistry, revokeArtifact, verifyRevocationRegistry, isRevoked } from "../index.js";

test("revocation registry records and resolves revoked artifacts", () => {
  let registry = createRevocationRegistry();
  registry = revokeArtifact(registry, "a".repeat(64), { reason: "key compromised", revoked_at: "2026-01-01T00:00:00.000Z" });

  assert.equal(verifyRevocationRegistry(registry).valid, true);
  assert.equal(isRevoked(registry, "a".repeat(64)).revoked, true);
  assert.equal(isRevoked(registry, "b".repeat(64)).revoked, false);
});

test("revocation registry mutation is detected", () => {
  let registry = createRevocationRegistry();
  registry = revokeArtifact(registry, "a".repeat(64));
  const mutated = structuredClone(registry);
  mutated.entries[0].artifact_hash = "b".repeat(64);
  assert.equal(verifyRevocationRegistry(mutated).valid, false);
});

test("revocation verifier fails closed when entries is not an array", () => {
  const registry = { type: "aml-revocation-registry/1", entries: { attacker: true }, head: null };

  assert.doesNotThrow(() => verifyRevocationRegistry(registry));
  assert.deepEqual(verifyRevocationRegistry(registry), { valid: false, reason: "invalid_entries" });
  assert.deepEqual(isRevoked(registry, "a".repeat(64)), {
    revoked: false,
    registry_valid: false,
    reason: "invalid_entries"
  });
});

test("revocation verifier fails closed on null and primitive entries", () => {
  for (const entry of [null, 42, "malformed"]) {
    const registry = { type: "aml-revocation-registry/1", entries: [entry], head: null };
    assert.doesNotThrow(() => verifyRevocationRegistry(registry));
    const result = verifyRevocationRegistry(registry);
    assert.equal(result.valid, false);
    assert.equal(result.reason, "invalid_entry");
    assert.equal(result.index, 0);
  }
});

test("revocation verifier fails closed when entry canonicalization is invalid", () => {
  const registry = {
    type: "aml-revocation-registry/1",
    entries: [{
      index: 0,
      previous_hash: null,
      artifact_hash: "a".repeat(64),
      reason: 1n,
      revoked_at: null,
      entry_hash: "not-relevant"
    }],
    head: "not-relevant"
  };

  assert.doesNotThrow(() => verifyRevocationRegistry(registry));
  const result = verifyRevocationRegistry(registry);
  assert.equal(result.valid, false);
  assert.equal(result.reason, "invalid_entry");
  assert.equal(result.index, 0);
});

test("revocation mutation rejects malformed registry structure before spreading it", () => {
  const registry = { type: "aml-revocation-registry/1", entries: {}, head: null };
  assert.throws(() => revokeArtifact(registry, "a".repeat(64)), /Invalid revocation registry entries/);
});
