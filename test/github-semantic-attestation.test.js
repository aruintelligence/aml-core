import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import {
  createMeaningManifest,
  signMeaningManifest,
  createMeaningLineage,
  appendMeaningLineage,
  createSemanticReleaseProof,
  createInTotoSemanticReleaseStatement,
  verifyInTotoSemanticReleaseStatement,
  AML_SEMANTIC_RELEASE_PREDICATE_V1
} from "../index.js";
import { prepareGitHubSemanticAttestation } from "../scripts/prepare-github-semantic-attestation.mjs";
import {
  buildGitHubAttestationVerifyArgs,
  verifyGitHubSemanticAttestationEvidence
} from "../tooling/githubSemanticAttestation.js";

const beforeSources = {
  "ui/card.aml": `transmission "release" {
  engram card {
    purpose: "Explain clearly"
    attention_cost: 2
    restoration_value: 5
  }
}`
};

const afterSources = {
  "ui/card.aml": `transmission "release" {
  engram card {
    purpose: "Create urgency"
    attention_cost: 4
    restoration_value: 3
  }
}`
};

function fixture() {
  const { privateKey } = crypto.generateKeyPairSync("ed25519");
  const privateKeyPem = privateKey.export({ type: "pkcs8", format: "pem" }).toString();
  const beforeManifest = createMeaningManifest(beforeSources);
  const afterManifest = createMeaningManifest(afterSources);
  const beforeAttestation = signMeaningManifest(beforeManifest, privateKeyPem, { signer: "release-bot", timestamp: "2026-09-09T08:00:00.000Z" });
  const afterAttestation = signMeaningManifest(afterManifest, privateKeyPem, { signer: "release-bot", timestamp: "2026-09-09T08:05:00.000Z" });
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
    timestamp: "2026-09-09T08:10:00.000Z",
    release_id: "v-next",
    previous_release_id: "v-prev"
  });
}

function githubEvidence(proof, proofBytes) {
  const statement = createInTotoSemanticReleaseStatement(proof);
  const digest = crypto.createHash("sha256").update(proofBytes).digest("hex");
  return [{
    verificationResult: {
      statement: {
        _type: "https://in-toto.io/Statement/v1",
        subject: [{ name: "release-proof.json", digest: { sha256: digest } }],
        predicateType: AML_SEMANTIC_RELEASE_PREDICATE_V1,
        predicate: structuredClone(statement.predicate)
      }
    }
  }];
}

test("GitHub semantic attestation preparation names the meaning state without mislabeling it as GitHub artifact subject", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "aml-github-attest-"));
  try {
    const proof = fixture();
    const result = prepareGitHubSemanticAttestation(proof, root);
    assert.equal(result.schema, "aml-github-semantic-attestation-input/2");
    assert.equal(result.predicate_type, AML_SEMANTIC_RELEASE_PREDICATE_V1);
    assert.equal(result.meaning_state_name, "aml-meaning-state:v-next");
    assert.equal(result.meaning_state_digest, `sha256:${proof.after_manifest_root_sha256}`);
    assert.equal(result.github_artifact_subject, "proof-file-bytes-via-actions-attest-subject-path");
    assert.equal("subject_name" in result, false);
    assert.equal("subject_digest" in result, false);
    assert.equal(result.proof_sha256, proof.proof_sha256);
    assert.equal(result.signer, "release-bot");
    assert.ok(fs.existsSync(result.predicate_path));
    assert.ok(fs.existsSync(result.statement_path));
    assert.ok(fs.existsSync(result.metadata_path));

    const predicate = JSON.parse(fs.readFileSync(result.predicate_path, "utf8"));
    const statement = JSON.parse(fs.readFileSync(result.statement_path, "utf8"));
    assert.deepEqual(predicate, statement.predicate);
    assert.equal(verifyInTotoSemanticReleaseStatement(statement).verified, true);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("GitHub semantic attestation preparation refuses an invalid AML proof", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "aml-github-attest-invalid-"));
  try {
    const proof = fixture();
    proof.signer = "forged";
    assert.throws(() => prepareGitHubSemanticAttestation(proof, root), /fully verified/);
    assert.equal(fs.existsSync(path.join(root, "aml-semantic-release-predicate.json")), false);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("semantic release attestation action uses real proof bytes as GitHub subject", () => {
  const action = fs.readFileSync("actions/semantic-release-attestation/action.yml", "utf8");
  assert.ok(action.includes("subject-path: ${{ inputs.proof-file }}"));
  assert.equal(action.includes("subject-digest: ${{ steps.prepare.outputs.meaning_state_digest }}"), false);
  assert.ok(action.includes(`predicate-type: ${AML_SEMANTIC_RELEASE_PREDICATE_V1}`));
  assert.ok(action.includes("predicate-path: ${{ steps.prepare.outputs.predicate_path }}"));
});

test("semantic release attestation action pins actions/attest and avoids shell input interpolation", () => {
  const action = fs.readFileSync("actions/semantic-release-attestation/action.yml", "utf8");
  assert.ok(action.includes("uses: actions/attest@1e69f48acb82d1966a394da916b4c1698aa569d6"));
  assert.ok(action.includes("AML_PROOF_FILE: ${{ inputs.proof-file }}"));
  const runBody = action.slice(action.indexOf("      run: |"), action.indexOf("    - id: attest"));
  assert.equal(runBody.includes("${{ inputs."), false);
  assert.ok(runBody.includes("crypto.randomBytes(16)"));
  assert.ok(runBody.includes("<<${delimiter}"));
});

test("GitHub verification command binds repo, signer repo, predicate and denies self-hosted runners by default", () => {
  const args = buildGitHubAttestationVerifyArgs({ proofFile: "release-proof.json", repo: "acme/app" });
  assert.deepEqual(args.slice(0, 3), ["attestation", "verify", "release-proof.json"]);
  assert.ok(args.includes("--repo"));
  assert.ok(args.includes("--signer-repo"));
  assert.ok(args.includes("--predicate-type"));
  assert.ok(args.includes(AML_SEMANTIC_RELEASE_PREDICATE_V1));
  assert.ok(args.includes("--deny-self-hosted-runners"));
  assert.equal(args.includes("acme/app; echo pwned"), false);

  const relaxed = buildGitHubAttestationVerifyArgs({ proofFile: "release-proof.json", repo: "acme/app", allowSelfHosted: true });
  assert.equal(relaxed.includes("--deny-self-hosted-runners"), false);
});

test("two-layer verifier accepts only exact GitHub file bytes plus exact AML predicate and proof", () => {
  const proof = fixture();
  const proofBytes = Buffer.from(`${JSON.stringify(proof, null, 2)}\n`, "utf8");
  const ghVerification = githubEvidence(proof, proofBytes);
  const result = verifyGitHubSemanticAttestationEvidence({ ghVerification, proof, proofBytes });
  assert.equal(result.verified, true);
  assert.equal(result.github_attestation_verified, true);
  assert.equal(result.proof_file_digest_valid, true);
  assert.equal(result.predicate_binding_valid, true);
  assert.equal(result.release_proof_valid, true);
  assert.equal(result.signer, "release-bot");
  assert.equal(result.meaning_state_sha256, proof.after_manifest_root_sha256);
});

test("two-layer verifier rejects digest, predicate, embedded-proof and empty-evidence tampering", () => {
  const proof = fixture();
  const proofBytes = Buffer.from(`${JSON.stringify(proof, null, 2)}\n`, "utf8");

  const wrongBytes = Buffer.concat([proofBytes, Buffer.from(" ")]);
  assert.equal(verifyGitHubSemanticAttestationEvidence({ ghVerification: githubEvidence(proof, proofBytes), proof, proofBytes: wrongBytes }).verified, false);

  const predicateTamper = githubEvidence(proof, proofBytes);
  predicateTamper[0].verificationResult.statement.predicate.release.id = "forged";
  assert.equal(verifyGitHubSemanticAttestationEvidence({ ghVerification: predicateTamper, proof, proofBytes }).verified, false);

  const proofTamper = githubEvidence(proof, proofBytes);
  proofTamper[0].verificationResult.statement.predicate.releaseProof.signer = "forged";
  assert.equal(verifyGitHubSemanticAttestationEvidence({ ghVerification: proofTamper, proof, proofBytes }).verified, false);

  assert.equal(verifyGitHubSemanticAttestationEvidence({ ghVerification: [], proof, proofBytes }).verified, false);
});
