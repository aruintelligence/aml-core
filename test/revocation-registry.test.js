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
