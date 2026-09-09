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
  verifyInTotoSemanticReleaseStatement,
  AML_SEMANTIC_RELEASE_PREDICATE_V1
} from "../index.js";
import { prepareGitHubSemanticAttestation } from "../scripts/prepare-github-semantic-attestation.mjs";

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

test("GitHub semantic attestation preparation emits verified predicate and statement", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "aml-github-attest-"));
  try {
    const proof = fixture();
    const result = prepareGitHubSemanticAttestation(proof, root);
    assert.equal(result.predicate_type, AML_SEMANTIC_RELEASE_PREDICATE_V1);
    assert.equal(result.subject_name, "aml-meaning-state:v-next");
    assert.equal(result.subject_digest, `sha256:${proof.after_manifest_root_sha256}`);
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
