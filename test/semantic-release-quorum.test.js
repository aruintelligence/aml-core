import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";

import {
  createMeaningManifest,
  signMeaningManifest,
  createMeaningLineage,
  appendMeaningLineage,
  createSemanticReleaseProof
} from "../index.js";
import {
  SEMANTIC_RELEASE_QUORUM_POLICY_PROTOCOL,
  createSemanticReleaseEndorsement,
  verifySemanticReleaseEndorsement,
  validateSemanticReleaseQuorumPolicy,
  fingerprintSemanticReleaseQuorumPolicy,
  verifySemanticReleaseQuorum
} from "../tooling/semanticReleaseQuorum.js";

const beforeSources = { "ui/app.aml": `transmission "app" { engram card { purpose: "before" attention_cost: 1 restoration_value: 3 } }` };
const afterSources = { "ui/app.aml": `transmission "app" { engram card { purpose: "after" attention_cost: 2 restoration_value: 4 } }` };

function keyPair() {
  const { privateKey, publicKey } = crypto.generateKeyPairSync("ed25519");
  return {
    privateKeyPem: privateKey.export({ type: "pkcs8", format: "pem" }).toString(),
    publicKeySha256: crypto.createHash("sha256").update(publicKey.export({ type: "spki", format: "der" })).digest("hex")
  };
}

function proofFixture() {
  const releaseKey = keyPair();
  const beforeManifest = createMeaningManifest(beforeSources);
  const afterManifest = createMeaningManifest(afterSources);
  const beforeAttestation = signMeaningManifest(beforeManifest, releaseKey.privateKeyPem, { signer: "release-bot", timestamp: "2026-09-09T12:00:00.000Z" });
  const afterAttestation = signMeaningManifest(afterManifest, releaseKey.privateKeyPem, { signer: "release-bot", timestamp: "2026-09-09T12:05:00.000Z" });
  let lineage = createMeaningLineage();
  lineage = appendMeaningLineage(lineage, beforeManifest, beforeAttestation);
  lineage = appendMeaningLineage(lineage, afterManifest, afterAttestation);
  return createSemanticReleaseProof({
    before_manifest: beforeManifest,
    before_attestation: beforeAttestation,
    after_manifest: afterManifest,
    after_attestation: afterAttestation,
    lineage,
    before_sources: beforeSources,
    after_sources: afterSources,
    private_key_pem: releaseKey.privateKeyPem,
    signer: "release-bot",
    timestamp: "2026-09-09T12:10:00.000Z",
    release_id: "release-quorum-1"
  });
}

function policy(keys, threshold = 2) {
  return {
    protocol: SEMANTIC_RELEASE_QUORUM_POLICY_PROTOCOL,
    policy_id: "production-quorum",
    threshold,
    trusted_keys: keys.map((key, index) => ({ public_key_sha256: key.publicKeySha256, signer: `approver-${index + 1}` }))
  };
}

test("2-of-3 independently trusted endorsements authorize one exact semantic release", () => {
  const proof = proofFixture();
  const keys = [keyPair(), keyPair(), keyPair()];
  const quorumPolicy = policy(keys, 2);
  const endorsements = [
    createSemanticReleaseEndorsement(proof, keys[0].privateKeyPem, { signer: "approver-1", timestamp: "2026-09-09T12:11:00.000Z" }),
    createSemanticReleaseEndorsement(proof, keys[1].privateKeyPem, { signer: "approver-2", timestamp: "2026-09-09T12:12:00.000Z" })
  ];
  const result = verifySemanticReleaseQuorum(proof, endorsements, quorumPolicy);
  assert.equal(result.verified, true);
  assert.equal(result.valid_trusted_endorsements, 2);
  assert.equal(result.threshold, 2);
  assert.equal(result.unique_trusted_keys.length, 2);
});

test("one valid trusted endorsement cannot satisfy a 2-of-3 policy", () => {
  const proof = proofFixture();
  const keys = [keyPair(), keyPair(), keyPair()];
  const result = verifySemanticReleaseQuorum(proof, [
    createSemanticReleaseEndorsement(proof, keys[0].privateKeyPem, { signer: "approver-1" })
  ], policy(keys, 2));
  assert.equal(result.verified, false);
  assert.equal(result.reason, "quorum_not_met");
  assert.equal(result.valid_trusted_endorsements, 1);
});

test("duplicate signatures from one trusted key count only once", () => {
  const proof = proofFixture();
  const keys = [keyPair(), keyPair(), keyPair()];
  const first = createSemanticReleaseEndorsement(proof, keys[0].privateKeyPem, { signer: "approver-1", timestamp: "2026-09-09T12:11:00.000Z" });
  const second = createSemanticReleaseEndorsement(proof, keys[0].privateKeyPem, { signer: "approver-1", timestamp: "2026-09-09T12:12:00.000Z" });
  const result = verifySemanticReleaseQuorum(proof, [first, second], policy(keys, 2));
  assert.equal(result.verified, false);
  assert.equal(result.valid_trusted_endorsements, 1);
  assert.ok(result.rejected_endorsements.some(item => item.reason === "duplicate_endorsement_key"));
});

test("cryptographically valid endorsement from an untrusted key counts zero", () => {
  const proof = proofFixture();
  const trusted = [keyPair(), keyPair(), keyPair()];
  const outsider = keyPair();
  const result = verifySemanticReleaseQuorum(proof, [
    createSemanticReleaseEndorsement(proof, trusted[0].privateKeyPem, { signer: "approver-1" }),
    createSemanticReleaseEndorsement(proof, outsider.privateKeyPem, { signer: "outsider" })
  ], policy(trusted, 2));
  assert.equal(result.verified, false);
  assert.equal(result.valid_trusted_endorsements, 1);
  assert.ok(result.rejected_endorsements.some(item => item.reason === "endorsement_key_not_trusted"));
});

test("trusted key with wrong signer constraint counts zero", () => {
  const proof = proofFixture();
  const keys = [keyPair(), keyPair()];
  const result = verifySemanticReleaseQuorum(proof, [
    createSemanticReleaseEndorsement(proof, keys[0].privateKeyPem, { signer: "wrong-label" }),
    createSemanticReleaseEndorsement(proof, keys[1].privateKeyPem, { signer: "approver-2" })
  ], policy(keys, 2));
  assert.equal(result.verified, false);
  assert.equal(result.valid_trusted_endorsements, 1);
  assert.ok(result.rejected_endorsements.some(item => item.reason === "endorsement_signer_constraint_mismatch"));
});

test("endorsement is bound to exact proof hash, release id, meaning root and lineage head", () => {
  const proof = proofFixture();
  const key = keyPair();
  for (const field of ["proof_sha256", "after_manifest_root_sha256", "lineage_head_sha256"]) {
    const endorsement = createSemanticReleaseEndorsement(proof, key.privateKeyPem, { signer: "approver" });
    endorsement[field] = "0".repeat(64);
    assert.equal(verifySemanticReleaseEndorsement(endorsement, proof).reason, "proof_binding_mismatch");
  }
  const endorsement = createSemanticReleaseEndorsement(proof, key.privateKeyPem, { signer: "approver" });
  endorsement.release_id = "another-release";
  assert.equal(verifySemanticReleaseEndorsement(endorsement, proof).reason, "proof_binding_mismatch");
});

test("signed endorsement material rejects signer/timestamp/hash/signature tampering", () => {
  const proof = proofFixture();
  const key = keyPair();
  const original = createSemanticReleaseEndorsement(proof, key.privateKeyPem, { signer: "approver", timestamp: "2026-09-09T12:15:00.000Z" });

  const signer = structuredClone(original);
  signer.signer = "forged";
  assert.equal(verifySemanticReleaseEndorsement(signer, proof).verified, false);

  const time = structuredClone(original);
  time.endorsed_at = "2026-09-09T12:16:00.000Z";
  assert.equal(verifySemanticReleaseEndorsement(time, proof).verified, false);

  const hash = structuredClone(original);
  hash.endorsement_sha256 = "f".repeat(64);
  assert.equal(verifySemanticReleaseEndorsement(hash, proof).verified, false);

  const signature = structuredClone(original);
  signature.signature_base64 = "A".repeat(signature.signature_base64.length);
  assert.equal(verifySemanticReleaseEndorsement(signature, proof).verified, false);
});

test("quorum policy threshold and exact canonical policy fingerprint fail closed", () => {
  const proof = proofFixture();
  const keys = [keyPair(), keyPair(), keyPair()];
  const quorumPolicy = policy(keys, 2);
  const policySha = fingerprintSemanticReleaseQuorumPolicy(quorumPolicy);
  assert.match(policySha, /^[a-f0-9]{64}$/);
  assert.equal(validateSemanticReleaseQuorumPolicy({ ...quorumPolicy, threshold: 0 }).valid, false);
  assert.equal(validateSemanticReleaseQuorumPolicy({ ...quorumPolicy, threshold: 4 }).valid, false);

  const endorsements = [
    createSemanticReleaseEndorsement(proof, keys[0].privateKeyPem, { signer: "approver-1" }),
    createSemanticReleaseEndorsement(proof, keys[1].privateKeyPem, { signer: "approver-2" })
  ];
  assert.equal(verifySemanticReleaseQuorum(proof, endorsements, quorumPolicy, { expectedPolicySha256: policySha }).verified, true);
  const mismatch = verifySemanticReleaseQuorum(proof, endorsements, quorumPolicy, { expectedPolicySha256: "0".repeat(64) });
  assert.equal(mismatch.verified, false);
  assert.equal(mismatch.reason, "policy_fingerprint_mismatch");
});
