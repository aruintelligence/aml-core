import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { execFileSync, spawnSync } from "node:child_process";

import {
  createMeaningManifest,
  signMeaningManifest,
  createMeaningLineage,
  appendMeaningLineage,
  createSemanticReleaseProof,
  createInTotoSemanticReleaseStatement,
  verifyInTotoSemanticReleaseStatement,
  IN_TOTO_STATEMENT_V1,
  AML_SEMANTIC_RELEASE_PREDICATE_V1
} from "../index.js";

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
  const proof = createSemanticReleaseProof({
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
  return { proof };
}

test("verified semantic release proof becomes an in-toto Statement v1", () => {
  const { proof } = fixture();
  const statement = createInTotoSemanticReleaseStatement(proof);
  assert.equal(statement._type, IN_TOTO_STATEMENT_V1);
  assert.equal(statement.predicateType, AML_SEMANTIC_RELEASE_PREDICATE_V1);
  assert.deepEqual(statement.subject, [{
    name: "aml-meaning-state:v-next",
    digest: { sha256: proof.after_manifest_root_sha256 }
  }]);
  assert.equal(statement.predicate.semantic.beforeRootSha256, proof.before_manifest_root_sha256);
  assert.equal(statement.predicate.semantic.afterRootSha256, proof.after_manifest_root_sha256);
  assert.equal(statement.predicate.attribution.signer, "release-bot");
  assert.equal(statement.predicate.attribution.proofSha256, proof.proof_sha256);

  const result = verifyInTotoSemanticReleaseStatement(statement);
  assert.equal(result.verified, true);
  assert.equal(result.attribution_bound, true);
  assert.equal(result.signer, "release-bot");
});

test("in-toto bridge rejects rewritten subject and derived predicate metadata", () => {
  for (const mutate of [
    statement => { statement.subject[0].digest.sha256 = "0".repeat(64); },
    statement => { statement.subject[0].name = "aml-meaning-state:forged"; },
    statement => { statement.predicate.semantic.afterRootSha256 = "0".repeat(64); },
    statement => { statement.predicate.semantic.changed = false; },
    statement => { statement.predicate.semantic.changeSummary.changed = 999; },
    statement => { statement.predicate.attribution.signer = "forged-signer"; },
    statement => { statement.predicate.attribution.proofSha256 = "0".repeat(64); },
    statement => { statement.predicate.release.id = "forged-release"; }
  ]) {
    const statement = createInTotoSemanticReleaseStatement(fixture().proof);
    mutate(statement);
    assert.equal(verifyInTotoSemanticReleaseStatement(statement).verified, false);
  }
});

test("in-toto bridge rejects wrong envelope contracts and nested proof tampering", () => {
  const first = createInTotoSemanticReleaseStatement(fixture().proof);
  first._type = "https://example.invalid/Statement/v1";
  assert.equal(verifyInTotoSemanticReleaseStatement(first).verified, false);

  const second = createInTotoSemanticReleaseStatement(fixture().proof);
  second.predicateType = "https://slsa.dev/provenance/v1";
  assert.equal(verifyInTotoSemanticReleaseStatement(second).verified, false);

  const third = createInTotoSemanticReleaseStatement(fixture().proof);
  third.predicate.releaseProof.signer = "forged";
  assert.equal(verifyInTotoSemanticReleaseStatement(third).verified, false);

  const fourth = createInTotoSemanticReleaseStatement(fixture().proof);
  fourth.subject.push({ name: "extra", digest: { sha256: "0".repeat(64) } });
  assert.equal(verifyInTotoSemanticReleaseStatement(fourth).verified, false);
});

test("in-toto bridge refuses to wrap an invalid semantic release proof", () => {
  const { proof } = fixture();
  proof.change_summary.changed = 99;
  assert.throws(() => createInTotoSemanticReleaseStatement(proof), /fully verified/);
});

test("predicate URI resolves to a checked-in machine-readable contract", () => {
  const schema = JSON.parse(fs.readFileSync("docs/predicates/semantic-release/v1.json", "utf8"));
  assert.equal(schema.$id, AML_SEMANTIC_RELEASE_PREDICATE_V1);
  assert.equal(schema.properties.schema.const, "aml-in-toto-semantic-release-predicate/1");
  assert.match(schema.description, /not SLSA build provenance/i);
});

test("aml-release-proof CLI exports and verifies the in-toto statement", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "aml-in-toto-"));
  try {
    const proofPath = path.join(root, "proof.json");
    const statementPath = path.join(root, "statement.json");
    fs.writeFileSync(proofPath, `${JSON.stringify(fixture().proof, null, 2)}\n`);
    const exported = execFileSync(process.execPath, ["bin/aml-release-proof.js", "in-toto", proofPath], { encoding: "utf8" });
    const statement = JSON.parse(exported);
    fs.writeFileSync(statementPath, `${JSON.stringify(statement, null, 2)}\n`);
    const verified = spawnSync(process.execPath, ["bin/aml-release-proof.js", "verify-in-toto", statementPath], { encoding: "utf8" });
    assert.equal(verified.status, 0, verified.stderr || verified.stdout);
    assert.equal(JSON.parse(verified.stdout).verified, true);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});
