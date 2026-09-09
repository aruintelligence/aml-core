import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";

import {
  createMeaningManifest,
  signMeaningManifest,
  createMeaningLineage,
  appendMeaningLineage,
  createSemanticReleaseProof,
  createInTotoSemanticReleaseStatement,
  AML_SEMANTIC_RELEASE_PREDICATE_V1,
  RELEASE_KEY_TRUST_POLICY_PROTOCOL,
  SEMANTIC_RELEASE_QUORUM_POLICY_PROTOCOL,
  createSemanticReleaseEndorsement,
  fingerprintSemanticReleaseQuorumPolicy,
  verifyGitHubSemanticAttestationEvidence
} from "../index.js";

const beforeSources = { "ui/app.aml": `transmission "app" { engram card { purpose: "before" attention_cost: 1 restoration_value: 3 } }` };
const afterSources = { "ui/app.aml": `transmission "app" { engram card { purpose: "after" attention_cost: 2 restoration_value: 4 } }` };

function keyPair() {
  const { privateKey, publicKey } = crypto.generateKeyPairSync("ed25519");
  return {
    privateKeyPem: privateKey.export({ type: "pkcs8", format: "pem" }).toString(),
    publicKeySha256: crypto.createHash("sha256").update(publicKey.export({ type: "spki", format: "der" })).digest("hex")
  };
}

function fixture() {
  const releaseKey = keyPair();
  const beforeManifest = createMeaningManifest(beforeSources);
  const afterManifest = createMeaningManifest(afterSources);
  const beforeAttestation = signMeaningManifest(beforeManifest, releaseKey.privateKeyPem, { signer: "release-bot", timestamp: "2026-09-09T13:00:00.000Z" });
  const afterAttestation = signMeaningManifest(afterManifest, releaseKey.privateKeyPem, { signer: "release-bot", timestamp: "2026-09-09T13:05:00.000Z" });
  let lineage = createMeaningLineage();
  lineage = appendMeaningLineage(lineage, beforeManifest, beforeAttestation);
  lineage = appendMeaningLineage(lineage, afterManifest, afterAttestation);
  const proof = createSemanticReleaseProof({
    before_manifest: beforeManifest,
    before_attestation: beforeAttestation,
    after_manifest: afterManifest,
    after_attestation: afterAttestation,
    lineage,
    before_sources: beforeSources,
    after_sources: afterSources,
    private_key_pem: releaseKey.privateKeyPem,
    signer: "release-bot",
    timestamp: "2026-09-09T13:10:00.000Z",
    release_id: "release-unified-1"
  });
  const proofBytes = Buffer.from(`${JSON.stringify(proof, null, 2)}\n`);
  const statement = createInTotoSemanticReleaseStatement(proof);
  const fileDigest = crypto.createHash("sha256").update(proofBytes).digest("hex");
  const ghVerification = [{ verificationResult: { statement: {
    _type: "https://in-toto.io/Statement/v1",
    subject: [{ name: "release-proof.json", digest: { sha256: fileDigest } }],
    predicateType: AML_SEMANTIC_RELEASE_PREDICATE_V1,
    predicate: structuredClone(statement.predicate)
  } } }];
  const trustPolicy = {
    protocol: RELEASE_KEY_TRUST_POLICY_PROTOCOL,
    policy_id: "release-key",
    trusted_keys: [{ public_key_sha256: proof.public_key_sha256, signer: "release-bot" }]
  };
  const approvers = [keyPair(), keyPair(), keyPair()];
  const quorumPolicy = {
    protocol: SEMANTIC_RELEASE_QUORUM_POLICY_PROTOCOL,
    policy_id: "release-board",
    threshold: 2,
    trusted_keys: approvers.map((key, index) => ({ public_key_sha256: key.publicKeySha256, signer: `approver-${index + 1}` }))
  };
  const endorsements = [
    createSemanticReleaseEndorsement(proof, approvers[0].privateKeyPem, { signer: "approver-1", timestamp: "2026-09-09T13:11:00.000Z" }),
    createSemanticReleaseEndorsement(proof, approvers[1].privateKeyPem, { signer: "approver-2", timestamp: "2026-09-09T13:12:00.000Z" })
  ];
  return { proof, proofBytes, ghVerification, trustPolicy, approvers, quorumPolicy, endorsements };
}

test("unified verifier requires GitHub, semantic proof, trusted release key, and M-of-N quorum together", () => {
  const f = fixture();
  const result = verifyGitHubSemanticAttestationEvidence({
    ghVerification: f.ghVerification,
    proof: f.proof,
    proofBytes: f.proofBytes,
    trustPolicy: f.trustPolicy,
    quorumEndorsements: f.endorsements,
    quorumPolicy: f.quorumPolicy,
    expectedQuorumPolicySha256: fingerprintSemanticReleaseQuorumPolicy(f.quorumPolicy)
  });
  assert.equal(result.verified, true);
  assert.equal(result.github_attestation_verified, true);
  assert.equal(result.release_proof_valid, true);
  assert.equal(result.release_key_trusted, true);
  assert.equal(result.quorum_verified, true);
  assert.equal(result.quorum_threshold, 2);
  assert.equal(result.quorum_valid_trusted_endorsements, 2);
});

test("perfect GitHub and semantic evidence still fails when quorum is one signature short", () => {
  const f = fixture();
  const result = verifyGitHubSemanticAttestationEvidence({
    ghVerification: f.ghVerification,
    proof: f.proof,
    proofBytes: f.proofBytes,
    trustPolicy: f.trustPolicy,
    quorumEndorsements: [f.endorsements[0]],
    quorumPolicy: f.quorumPolicy
  });
  assert.equal(result.verified, false);
  assert.equal(result.release_proof_valid, true);
  assert.equal(result.release_key_trusted, true);
  assert.equal(result.quorum_verified, false);
  assert.equal(result.reason, "quorum_not_met");
});

test("unified verifier rejects a moved quorum policy through pinned canonical policy hash", () => {
  const f = fixture();
  const expected = fingerprintSemanticReleaseQuorumPolicy(f.quorumPolicy);
  const changedPolicy = structuredClone(f.quorumPolicy);
  changedPolicy.threshold = 3;
  const result = verifyGitHubSemanticAttestationEvidence({
    ghVerification: f.ghVerification,
    proof: f.proof,
    proofBytes: f.proofBytes,
    quorumEndorsements: f.endorsements,
    quorumPolicy: changedPolicy,
    expectedQuorumPolicySha256: expected
  });
  assert.equal(result.verified, false);
  assert.equal(result.reason, "policy_fingerprint_mismatch");
  assert.equal(result.quorum_policy_fingerprint_valid, false);
});

test("unified verifier requires quorum policy and endorsements as one atomic input pair", () => {
  const f = fixture();
  const missingEndorsements = verifyGitHubSemanticAttestationEvidence({ ghVerification: f.ghVerification, proof: f.proof, proofBytes: f.proofBytes, quorumPolicy: f.quorumPolicy });
  assert.equal(missingEndorsements.verified, false);
  assert.equal(missingEndorsements.reason, "quorum_policy_and_endorsements_required");

  const missingPolicy = verifyGitHubSemanticAttestationEvidence({ ghVerification: f.ghVerification, proof: f.proof, proofBytes: f.proofBytes, quorumEndorsements: f.endorsements });
  assert.equal(missingPolicy.verified, false);
  assert.equal(missingPolicy.reason, "quorum_policy_and_endorsements_required");
});

test("CLI surface exposes quorum flags without shell interpolation", () => {
  const cli = fs.readFileSync("bin/aml-github-attestation.js", "utf8");
  for (const flag of ["--quorum-endorsements", "--quorum-policy", "--quorum-policy-sha256"]) assert.ok(cli.includes(flag));
  assert.ok(cli.includes('spawnSync("gh", ghArgs, { encoding: "utf8", shell: false'));
});
