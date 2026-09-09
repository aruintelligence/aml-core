import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";

import {
  createMeaningManifest,
  signMeaningManifest,
  createMeaningLineage,
  appendMeaningLineage,
  createSemanticReleaseProof,
  createInTotoSemanticReleaseStatement
} from "../index.js";
import {
  RELEASE_KEY_TRUST_POLICY_PROTOCOL,
  validateReleaseKeyTrustPolicy,
  verifyTrustedSemanticReleaseProof
} from "../tooling/releaseKeyTrust.js";
import { verifyGitHubSemanticAttestationEvidence } from "../tooling/githubSemanticAttestation.js";
import { AML_SEMANTIC_RELEASE_PREDICATE_V1 } from "../compiler/inTotoSemanticRelease.js";

const beforeSources = { "ui/app.aml": `transmission "app" { engram card { purpose: "before" attention_cost: 1 restoration_value: 3 } }` };
const afterSources = { "ui/app.aml": `transmission "app" { engram card { purpose: "after" attention_cost: 2 restoration_value: 4 } }` };

function fixture() {
  const { privateKey } = crypto.generateKeyPairSync("ed25519");
  const privateKeyPem = privateKey.export({ type: "pkcs8", format: "pem" }).toString();
  const beforeManifest = createMeaningManifest(beforeSources);
  const afterManifest = createMeaningManifest(afterSources);
  const beforeAttestation = signMeaningManifest(beforeManifest, privateKeyPem, { signer: "release-bot", timestamp: "2026-09-09T10:00:00.000Z" });
  const afterAttestation = signMeaningManifest(afterManifest, privateKeyPem, { signer: "release-bot", timestamp: "2026-09-09T10:05:00.000Z" });
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
    private_key_pem: privateKeyPem,
    signer: "release-bot",
    timestamp: "2026-09-09T10:10:00.000Z",
    release_id: "release-1"
  });
}

function policyFor(proof, signer = "release-bot") {
  return {
    protocol: RELEASE_KEY_TRUST_POLICY_PROTOCOL,
    policy_id: "production-release-keys",
    trusted_keys: [{ public_key_sha256: proof.public_key_sha256, signer }]
  };
}

function githubEvidence(proof, proofBytes) {
  const inner = createInTotoSemanticReleaseStatement(proof);
  const digest = crypto.createHash("sha256").update(proofBytes).digest("hex");
  return [{ verificationResult: { statement: {
    _type: "https://in-toto.io/Statement/v1",
    subject: [{ name: "release-proof.json", digest: { sha256: digest } }],
    predicateType: AML_SEMANTIC_RELEASE_PREDICATE_V1,
    predicate: structuredClone(inner.predicate)
  } } }];
}

test("external release-key policy upgrades valid signature into explicit trusted-key verification", () => {
  const proof = fixture();
  const result = verifyTrustedSemanticReleaseProof(proof, policyFor(proof));
  assert.equal(result.verified, true);
  assert.equal(result.semantic_proof_valid, true);
  assert.equal(result.trust_policy_valid, true);
  assert.equal(result.release_key_trusted, true);
  assert.equal(result.signer_constraint_valid, true);
  assert.equal(result.policy_id, "production-release-keys");
  assert.equal(result.public_key_sha256, proof.public_key_sha256);
});

test("valid self-signed semantic proof fails when its release key is not externally trusted", () => {
  const proof = fixture();
  const policy = policyFor(proof);
  policy.trusted_keys[0].public_key_sha256 = "0".repeat(64);
  const result = verifyTrustedSemanticReleaseProof(proof, policy);
  assert.equal(result.verified, false);
  assert.equal(result.semantic_proof_valid, true);
  assert.equal(result.release_key_trusted, false);
  assert.equal(result.reason, "release_key_not_trusted");
});

test("trusted fingerprint still fails a mismatched signer constraint", () => {
  const proof = fixture();
  const result = verifyTrustedSemanticReleaseProof(proof, policyFor(proof, "different-release-bot"));
  assert.equal(result.verified, false);
  assert.equal(result.release_key_trusted, true);
  assert.equal(result.signer_constraint_valid, false);
  assert.equal(result.reason, "signer_constraint_mismatch");
});

test("release-key policy rejects duplicate, malformed and empty trust roots", () => {
  const proof = fixture();
  const duplicate = policyFor(proof);
  duplicate.trusted_keys.push(structuredClone(duplicate.trusted_keys[0]));
  assert.equal(validateReleaseKeyTrustPolicy(duplicate).valid, false);

  const malformed = policyFor(proof);
  malformed.trusted_keys[0].public_key_sha256 = "NOT-A-HASH";
  assert.equal(validateReleaseKeyTrustPolicy(malformed).valid, false);

  assert.equal(validateReleaseKeyTrustPolicy({ protocol: RELEASE_KEY_TRUST_POLICY_PROTOCOL, trusted_keys: [] }).valid, false);
});

test("GitHub plus AML verifier requires external release-key trust when policy is supplied", () => {
  const proof = fixture();
  const proofBytes = Buffer.from(`${JSON.stringify(proof, null, 2)}\n`);
  const evidence = githubEvidence(proof, proofBytes);

  const trusted = verifyGitHubSemanticAttestationEvidence({ ghVerification: evidence, proof, proofBytes, trustPolicy: policyFor(proof) });
  assert.equal(trusted.verified, true);
  assert.equal(trusted.release_key_trust_required, true);
  assert.equal(trusted.release_key_trusted, true);
  assert.equal(trusted.trust_policy_id, "production-release-keys");

  const untrustedPolicy = policyFor(proof);
  untrustedPolicy.trusted_keys[0].public_key_sha256 = "f".repeat(64);
  const rejected = verifyGitHubSemanticAttestationEvidence({ ghVerification: evidence, proof, proofBytes, trustPolicy: untrustedPolicy });
  assert.equal(rejected.verified, false);
  assert.equal(rejected.release_proof_valid, true);
  assert.equal(rejected.reason, "release_key_not_trusted");
});
