import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { canonicalJSONStringify } from "../protocol/canonicalJson.js";
import { signBrandAuthorization } from "../runtime/brandAuthorization.js";
import { verifyBrandClaim } from "../runtime/brandClaim.js";
import { createRevocationRegistry, revokeArtifact } from "../runtime/revocationRegistry.js";

function fixture() {
  const { privateKey } = crypto.generateKeyPairSync("ed25519");
  const credential = signBrandAuthorization({
    grantee: "Example Integrator LLC", marks: ["ĀML Compatible™"],
    uses: ["official-compatible-badge"], authorization_id: "buyer-claim-1",
    issued_at: "2020-01-01T00:00:00Z", expires_at: "2100-01-01T00:00:00Z"
  }, privateKey.export({ type: "pkcs8", format: "pem" }));
  const roots = {
    type: "aml-brand-trust-roots/1", owner: "ĀRU Intelligence Inc.", status: "active",
    active_keys: [{ key_id: "example-root", public_key_sha256: credential.public_key_sha256 }], revoked_keys: []
  };
  const revocations = createRevocationRegistry();
  const policy = {
    type: "aml-brand-claim-policy/1", grantee: "Example Integrator LLC",
    mark: "ĀML Compatible™", permitted_use: "official-compatible-badge",
    trust_registry_sha256: crypto.createHash("sha256").update(canonicalJSONStringify(roots)).digest("hex"),
    revocation_head: revocations.head
  };
  return { credential, roots, revocations, policy };
}

test("exact-use claim requires buyer-pinned trust and revocation snapshots", () => {
  const { credential, roots, revocations, policy } = fixture();
  const verified = verifyBrandClaim(credential, roots, revocations, policy);
  assert.equal(verified.claim_verified, true);
  assert.equal(verified.official, true);
  assert.equal(verified.clock_source, "local_system");
  assert.equal(verified.credential_revocation_checked, true);
  assert.equal(verified.evidence_scope, "buyer_pinned_snapshots");
  assert.deepEqual(verified.claim_scope, {
    grantee: policy.grantee, mark: policy.mark, permitted_use: policy.permitted_use
  });
  assert.equal(verifyBrandClaim(credential, roots, null, policy).reason, "revocation_registry_required");
  assert.equal(verifyBrandClaim(credential, roots, revocations, { ...policy, revocation_head: undefined }).reason, "invalid_claim_policy");
});

test("a substituted root, rollback, and a newly revoked credential fail closed", () => {
  const { credential, roots, revocations, policy } = fixture();
  const stalePolicy = { ...policy };
  const revoked = revokeArtifact(revocations, credential.credential_hash);
  const currentPolicy = { ...policy, revocation_head: revoked.head };
  assert.equal(verifyBrandClaim(credential, roots, revocations, currentPolicy).reason, "revocation_snapshot_mismatch");
  assert.equal(verifyBrandClaim(credential, roots, revoked, stalePolicy).reason, "revocation_snapshot_mismatch");
  assert.equal(verifyBrandClaim(credential, roots, revoked, currentPolicy).reason, "revoked");

  const substitutedRoots = { ...roots, status: "rotating" };
  assert.equal(verifyBrandClaim(credential, substitutedRoots, revocations, policy).reason, "trust_registry_snapshot_mismatch");
  const alteredRoots = { ...roots, active_keys: [] };
  assert.equal(verifyBrandClaim(credential, alteredRoots, revocations, policy).reason, "trust_registry_snapshot_mismatch");

  const { privateKey: attackerKey } = crypto.generateKeyPairSync("ed25519");
  const counterfeit = signBrandAuthorization({
    grantee: policy.grantee, marks: [policy.mark], uses: [policy.permitted_use]
  }, attackerKey.export({ type: "pkcs8", format: "pem" }));
  const counterfeitRoots = {
    ...roots, active_keys: [{ public_key_sha256: counterfeit.public_key_sha256 }]
  };
  assert.equal(verifyBrandClaim(counterfeit, counterfeitRoots, revocations, policy).reason,
    "trust_registry_snapshot_mismatch");
});

test("a valid official signer does not grant a different grantee, mark, or use", () => {
  const { credential, roots, revocations, policy } = fixture();
  for (const [field, value, reason] of [
    ["grantee", "Another Integrator", "grantee_mismatch"],
    ["mark", "ĀML Certified™", "mark_not_permitted"],
    ["permitted_use", "resale", "use_not_permitted"]
  ]) {
    const result = verifyBrandClaim(credential, roots, revocations, { ...policy, [field]: value });
    assert.equal(result.claim_verified, false);
    assert.equal(result.official, true);
    assert.equal(result.reason, reason);
  }
  assert.equal(verifyBrandClaim(credential, roots, revocations, {}).reason, "invalid_claim_policy");
});

test("buyer policy CLI exits successfully only for the exact pinned claim", () => {
  const { credential, roots, revocations, policy } = fixture();
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "aml-brand-claim-"));
  try {
    const paths = ["credential.json", "roots.json", "revocations.json", "policy.json"]
      .map((name) => path.join(directory, name));
    [credential, roots, revocations, policy].forEach((value, index) => fs.writeFileSync(paths[index], JSON.stringify(value)));
    const cwd = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
    const run = () => spawnSync(process.execPath, ["bin/aml-brand-verify.js", ...paths], { cwd, encoding: "utf8" });
    const accepted = run();
    assert.equal(accepted.status, 0, accepted.stderr || accepted.stdout);
    assert.equal(JSON.parse(accepted.stdout).claim_verified, true);
    fs.writeFileSync(paths[3], JSON.stringify({ ...policy, permitted_use: "resale" }));
    const rejected = run();
    assert.equal(rejected.status, 1);
    assert.equal(JSON.parse(rejected.stdout).reason, "use_not_permitted");
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});
